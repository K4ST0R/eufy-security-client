import { DeviceSmartLockMessage, DoorbellPushMessage } from "./model";

export interface MQTTServiceEvents {
  connect: () => void;
  close: () => void;
  "lock message": (message: DeviceSmartLockMessage) => void;
  "doorbell message": (message: DoorbellPushMessage) => void;
}
