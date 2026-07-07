export interface DeviceSmartLockNotifyData {
  stationSn: string;
  deviceSn: string;
  eventType: number;
  eventTime: number;
  shortUserId: string;
  unknown1: string;
  nickName: string;
  userId: string;
  unknown2: string;
  deviceName: string;
  unknown3: string;
  lockState: string;
}

export interface DeviceSmartLockNotify {
  timestamp: number;
  uuid: string;
  data: DeviceSmartLockNotifyData;
}

export interface DeviceSmartLockMessage {
  eventType: number;
  userId: string;
  data: DeviceSmartLockNotify;
}

/**
 * Doorbell/camera push event delivered over MQTT on `/phone/doorbell/<device_sn>/push_message`.
 * Decoded from the eufy protobuf payload (fields captured from the real app):
 *   #1 event_type (DoorbellPushEvent: 3101 motion, 3103 ring, …), #3 event id,
 *   #15{#1 push_time(ms), #20{#7 file name, #10 station sn, #11 device sn}}.
 */
export interface DoorbellPushMessage {
  event_type: number;
  event_id: string;
  push_time: number;
  station_sn: string;
  device_sn: string;
  file_name: string;
}
