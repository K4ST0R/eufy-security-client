import * as mqtt from "mqtt";
import { TypedEmitter } from "tiny-typed-emitter";
import { readFileSync } from "fs";
import * as path from "path";
import { load, Root } from "protobufjs";

import { MQTTServiceEvents } from "./interface";
import { DeviceSmartLockMessage, DoorbellPushMessage } from "./model";
import { getError } from "../utils";
import { rootMainLogger, rootMQTTLogger } from "../logging";
import { ensureError } from "../error";

export class MQTTService extends TypedEmitter<MQTTServiceEvents> {
  private readonly CLIENT_ID_FORMAT = "android_EufySecurity_<user_id>_<android_id>";
  private readonly USERNAME_FORMAT = "eufy_<user_id>";
  private readonly SUBSCRIBE_NOTICE_FORMAT = "/phone/<user_id>/notice";
  private readonly SUBSCRIBE_LOCK_FORMAT = "/phone/smart_lock/<device_sn>/push_message";
  private readonly SUBSCRIBE_DOORBELL_FORMAT = "/phone/doorbell/<device_sn>/push_message";

  private static proto: Root | null = null;

  private connected = false;
  private client: mqtt.MqttClient | null = null;
  private connecting = false;

  private clientID?: string;
  private androidID?: string;
  private apiBase?: string;
  private email?: string;

  private subscribeLocks: Array<string> = [];
  private subscribeDoorbells: Array<string> = [];
  // True while no live client owns the connection (none yet, or the last one was `.end()`ed).
  // Guards against spawning a second mqtt client (same clientId) during an auto-reconnect gap.
  private clientEnded = true;

  private deviceSmartLockMessageModel: any;

  private constructor() {
    super();

    this.deviceSmartLockMessageModel = MQTTService.proto!.lookupType("DeviceSmartLockMessage");
  }

  public static async init(): Promise<MQTTService> {
    try {
      this.proto = await load(path.join(__dirname, "./proto/lock.proto"));
    } catch (error) {
      rootMainLogger.error("Error loading MQTT proto lock file", { error: ensureError(error) });
    }
    return new MQTTService();
  }

  private parseSmartLockMessage(data: Buffer): DeviceSmartLockMessage {
    const message = this.deviceSmartLockMessageModel.decode(data);
    const object = this.deviceSmartLockMessageModel.toObject(message, {
      longs: String,
      enums: String,
      bytes: String,
    });
    return object as DeviceSmartLockMessage;
  }

  private getMQTTBrokerUrl(apiBase: string): string {
    // Known hosts first (some have special, non-derivable mappings, e.g. the China-QA
    // app host on anker-in.com uses the eufylife.com QA broker).
    switch (apiBase) {
      case "https://security-app.eufylife.com":
        return "mqtts://security-mqtt.eufylife.com";
      case "https://security-app-ci.eufylife.com":
        return "mqtts://security-mqtt-ci.eufylife.com";
      case "https://security-app-qa.eufylife.com":
      case "https://security-app-cn-qa.anker-in.com":
        return "mqtts://security-mqtt-qa.eufylife.com";
      case "https://security-app-eu.eufylife.com":
        return "mqtts://security-mqtt-eu.eufylife.com";
      case "https://security-app-short-qa.eufylife.com":
        return "mqtts://security-mqtt-short-qa.eufylife.com";
    }
    // Unknown host: derive the region-specific broker from it instead of always falling
    // back to the global broker. The eufy MQTT broker is region-locked, so a non-global
    // account sent to the global broker is rejected with CONNACK "Not authorized" (5).
    // e.g. https://security-app-eu.eufylife.com -> mqtts://security-mqtt-eu.eufylife.com
    if (apiBase.includes("security-app")) {
      return apiBase.replace(/^https?:\/\//, "mqtts://").replace("security-app", "security-mqtt");
    }
    return "mqtts://security-mqtt.eufylife.com";
  }

  public connect(clientID: string, androidID: string, apiBase: string, email: string): void {
    this.clientID = clientID;
    this.androidID = androidID;
    this.apiBase = apiBase;
    this.email = email;
    if (
      !this.connected &&
      !this.connecting &&
      this.clientEnded &&
      this.clientID &&
      this.androidID &&
      this.apiBase &&
      this.email &&
      (this.subscribeLocks.length > 0 || this.subscribeDoorbells.length > 0)
    ) {
      this.connecting = true;
      this.clientEnded = false;
      this.client = mqtt.connect(this.getMQTTBrokerUrl(apiBase), {
        keepalive: 60,
        clean: true,
        reschedulePings: true,
        resubscribe: true,
        port: 8789,
        username: this.USERNAME_FORMAT.replace("<user_id>", clientID),
        password: email,
        ca: readFileSync(path.join(__dirname, "./mqtt-eufy.crt")),
        clientId: this.CLIENT_ID_FORMAT.replace("<user_id>", clientID).replace("<android_id>", androidID),
        rejectUnauthorized: false, // Some eufy mqtt servers have an expired certificate :(
      });
      this.client.on("connect", (_connack) => {
        this.connected = true;
        this.connecting = false;
        this.emit("connect");
        this.client!.subscribe(this.SUBSCRIBE_NOTICE_FORMAT.replace("<user_id>", clientID), { qos: 1 });

        if (this.subscribeLocks.length > 0) {
          let lock;
          while ((lock = this.subscribeLocks.shift()) !== undefined) {
            this._subscribeLock(lock);
          }
        }

        if (this.subscribeDoorbells.length > 0) {
          let doorbell;
          while ((doorbell = this.subscribeDoorbells.shift()) !== undefined) {
            this._subscribeDoorbell(doorbell);
          }
        }
      });
      this.client.on("close", () => {
        this.connected = false;
        this.emit("close");
      });
      this.client.on("error", (error) => {
        this.connecting = false;
        rootMQTTLogger.error("MQTT Error", { error: getError(error) });
        if (
          (error as any).code === 1 ||
          (error as any).code === 2 ||
          (error as any).code === 4 ||
          (error as any).code === 5
        ) {
          this.client?.end();
          this.clientEnded = true;
        }
      });
      this.client.on("message", (topic, message, _packet) => {
        if (topic.includes("smart_lock")) {
          const parsedMessage = this.parseSmartLockMessage(message);
          rootMQTTLogger.debug("Received a smart lock message over MQTT", { message: parsedMessage });
          this.emit("lock message", parsedMessage);
        } else if (topic.includes("doorbell")) {
          try {
            const parsedMessage = MQTTService.parseDoorbellPushMessage(message);
            rootMQTTLogger.debug("Received a doorbell push message over MQTT", { topic: topic, message: parsedMessage });
            if (parsedMessage.device_sn !== "" && parsedMessage.event_type > 0) {
              this.emit("doorbell message", parsedMessage);
            } else {
              rootMQTTLogger.debug("Ignored an unparseable doorbell push message over MQTT", {
                topic: topic,
                message: message.toString("hex"),
              });
            }
          } catch (error) {
            rootMQTTLogger.error("Error parsing doorbell push message over MQTT", {
              error: getError(ensureError(error)),
              topic: topic,
              message: message.toString("hex"),
            });
          }
        } else {
          rootMQTTLogger.debug("MQTT message received", { topic: topic, message: message.toString("hex") });
        }
      });
    }
  }

  private _subscribeLock(deviceSN: string): void {
    this.client?.subscribe(
      this.SUBSCRIBE_LOCK_FORMAT.replace("<device_sn>", deviceSN),
      { qos: 1 },
      (error, granted) => {
        if (error) {
          rootMQTTLogger.error(`Subscribe error for lock ${deviceSN}`, { error: getError(error), deviceSN: deviceSN });
        }
        if (granted) {
          rootMQTTLogger.info(`Successfully registered to MQTT notifications for lock ${deviceSN}`);
        }
      }
    );
  }

  public subscribeLock(deviceSN: string): void {
    if (this.connected) {
      this._subscribeLock(deviceSN);
    } else {
      if (!this.subscribeLocks.includes(deviceSN)) {
        this.subscribeLocks.push(deviceSN);
      }
      if (this.clientID && this.androidID && this.apiBase && this.email)
        this.connect(this.clientID, this.androidID, this.apiBase, this.email);
    }
  }

  private _subscribeDoorbell(deviceSN: string): void {
    this.client?.subscribe(
      this.SUBSCRIBE_DOORBELL_FORMAT.replace("<device_sn>", deviceSN),
      { qos: 1 },
      (error, granted) => {
        if (error) {
          rootMQTTLogger.error(`Subscribe error for doorbell ${deviceSN}`, {
            error: getError(error),
            deviceSN: deviceSN,
          });
        }
        if (granted) {
          rootMQTTLogger.info(`Successfully registered to MQTT notifications for doorbell ${deviceSN}`);
        }
      }
    );
  }

  public subscribeDoorbell(deviceSN: string): void {
    if (this.connected) {
      this._subscribeDoorbell(deviceSN);
    } else {
      if (!this.subscribeDoorbells.includes(deviceSN)) {
        this.subscribeDoorbells.push(deviceSN);
      }
      if (this.clientID && this.androidID && this.apiBase && this.email)
        this.connect(this.clientID, this.androidID, this.apiBase, this.email);
    }
  }

  /**
   * Decode the eufy doorbell/camera push protobuf (topic `/phone/doorbell/<sn>/push_message`).
   * Tolerant walker: only the fields we need are pulled, unknown fields are skipped, so a firmware
   * that adds fields won't break parsing. Layout (reversed from the real app, eBPF capture):
   *   #1 event_type, #3 event id, #15{ #1 push_time(ms), #20{ #7 file name, #10 station, #11 device } }.
   */
  public static parseDoorbellPushMessage(buf: Buffer): DoorbellPushMessage {
    type Field = { wire: number; num: number; buf: Buffer | null };
    const parse = (b: Buffer): Map<number, Field[]> => {
      const map = new Map<number, Field[]>();
      let p = 0;
      const varint = (): number => {
        let shift = 0;
        let val = 0;
        let byte = 0;
        do {
          byte = b[p++];
          val += (byte & 0x7f) * Math.pow(2, shift);
          shift += 7;
        } while (byte & 0x80 && p < b.length);
        return val;
      };
      while (p < b.length) {
        const tag = varint();
        const field = Math.floor(tag / 8);
        const wire = tag & 7;
        let entry: Field;
        if (wire === 0) {
          entry = { wire, num: varint(), buf: null };
        } else if (wire === 2) {
          const len = varint();
          entry = { wire, num: 0, buf: b.subarray(p, p + len) };
          p += len;
        } else if (wire === 5) {
          if (p + 4 > b.length) break;
          entry = { wire, num: b.readUInt32LE(p), buf: null };
          p += 4;
        } else if (wire === 1) {
          if (p + 8 > b.length) break;
          entry = { wire, num: Number(b.readBigUInt64LE(p)), buf: null };
          p += 8;
        } else {
          break;
        }
        const list = map.get(field);
        if (list) list.push(entry);
        else map.set(field, [entry]);
      }
      return map;
    };

    const firstBuf = (m: Map<number, Field[]>, f: number): Buffer | null => {
      const e = m.get(f);
      return e && e[0].buf ? e[0].buf : null;
    };
    const firstNum = (m: Map<number, Field[]>, f: number): number => {
      const e = m.get(f);
      return e ? e[0].num : 0;
    };
    const firstStr = (m: Map<number, Field[]>, f: number): string => {
      const b = firstBuf(m, f);
      return b ? b.toString("utf8") : "";
    };

    const top = parse(buf);
    const detailBuf = firstBuf(top, 15);
    const detail = detailBuf ? parse(detailBuf) : new Map<number, Field[]>();
    const bodyBuf = firstBuf(detail, 20);
    const body = bodyBuf ? parse(bodyBuf) : new Map<number, Field[]>();

    return {
      event_type: firstNum(top, 1),
      event_id: firstStr(top, 3),
      push_time: firstNum(detail, 1),
      file_name: firstStr(body, 7),
      station_sn: firstStr(body, 10),
      device_sn: firstStr(body, 11),
    };
  }

  public isConnected(): boolean {
    return this.connected;
  }

  public close(): void {
    if (this.connected) {
      this.client?.end(true);
      this.clientEnded = true;
      this.connected = false;
      this.connecting = false;
    }
  }
}
