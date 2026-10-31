export interface RouterBrandSpec {
  id: string;
  brand: string;
  modelSeries: string;
  protocol: string;
  defaultGateway: string;
  supported: boolean;
  supportsDeviceList: boolean;
  authMethod: string;
  compatibilityNote: string;
}

export interface NetworkProfile {
  id: number;
  ssid: string;
  band: string;
  securityType: string;
  signalDbm: number;
  bssid: string;
  routerBrandId: string;
  routerBrandName: string;
  protocol: string;
  compatibilityNote: string;
  gatewayIp: string;
  routerIp: string;
  adminUsername: string;
  hasAdminCredentials: boolean;
  currentPassword: string | null;
  routerLivePassword: string | null;
  encryptedPreview: string | null;
  passwordRetrievalStatus: string;
  routerCompatibilityStatus: string;
  connectionStatus: 'LIVE' | 'OFFLINE' | 'UNSUPPORTED';
  isSupported: boolean;
  isActiveConnection: boolean;
  monitoringEnabled: boolean;
  pollIntervalSec: number;
  lastCheckedIso: string | null;
  lastChangeDate: string | null;
  lastChangeTime: string | null;
  lastChangeIso: string | null;
}

export interface ConnectedDeviceItem {
  id: number;
  networkId: number;
  ssid: string;
  hostname: string;
  ipAddress: string;
  macAddress: string;
  manufacturer: string;
  firstConnectedIso: string;
  lastSeenIso: string;
  connectionStatus: 'LIVE' | 'OFFLINE';
  verificationMethod: string;
  isNewlyDetected: boolean;
}

export interface PasswordHistoryItem {
  id: number;
  networkId: number;
  ssid: string;
  previousPassword: string;
  newPassword: string;
  encryptedRecordPreview: string;
  changeDate: string;
  changeTime: string;
  timestampIso: string;
  routerBrand: string;
  detectionSource: string;
  detectionStatus: string;
}

export interface NotificationItem {
  id: number;
  networkId: number;
  ssid: string;
  alertType:
    | 'password_changed'
    | 'device_connected'
    | 'device_disconnected'
    | 'router_connectivity';
  title: string;
  message: string;
  previousPassword: string;
  newPassword: string;
  deviceHostname: string | null;
  deviceIp: string | null;
  deviceMac: string | null;
  deviceManufacturer: string | null;
  changeDate: string;
  changeTime: string;
  timestampIso: string;
  routerBrand: string;
  isRead: boolean;
}

export interface CompanionStatus {
  agentConnected: boolean;
  agentVersion: string;
  lastHeartbeatIso: string;
  pollCyclesCompleted: number;
}

export interface HostNetworkTelemetry {
  hostname: string;
  platform: string;
  localIp: string | null;
  macAddress: string | null;
  interfaceName: string | null;
  defaultGatewayIp: string | null;
  detectedSsid: string | null;
  detectedBssid: string | null;
  arpNeighborsCount: number;
  detectionMethod: string;
}

export interface SecurityInfo {
  encryptionAlgorithm: string;
  companionApiToken: string;
  rateLimitActive: boolean;
  sqliteWalMode: boolean;
}

export interface DashboardState {
  networks: NetworkProfile[];
  activeNetwork: NetworkProfile | null;
  devices: ConnectedDeviceItem[];
  totalConnectedDevices: number;
  newlyDetectedDevicesCount: number;
  history: PasswordHistoryItem[];
  notifications: NotificationItem[];
  unreadCount: number;
  routerBrands: RouterBrandSpec[];
  hostEnvironment: HostNetworkTelemetry;
  securityInfo: SecurityInfo;
  companion: CompanionStatus;
}

export interface PasswordChangedEventPayload {
  notificationId: number;
  networkId: number;
  ssid: string;
  alertType?: string;
  title?: string;
  previousPassword: string;
  newPassword: string;
  changeDate: string;
  changeTime: string;
  timestampIso: string;
  routerBrand: string;
}

export interface DeviceEventPayload {
  notificationId: number;
  networkId: number;
  ssid: string;
  alertType: 'device_connected' | 'device_disconnected';
  title: string;
  deviceHostname: string;
  deviceIp: string;
  deviceMac: string;
  deviceManufacturer: string;
  changeDate: string;
  changeTime: string;
  timestampIso: string;
  routerBrand: string;
}

export interface VerificationStepResult {
  step: number;
  name: string;
  status: 'PASSED' | 'FAILED';
  verificationDetail: string;
  timestamp: string;
}
