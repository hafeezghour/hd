import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  Bell,
  Check,
  CheckCircle2,
  Copy,
  Download,
  Eye,
  EyeOff,
  History,
  KeyRound,
  Laptop,
  Lock,
  Moon,
  Network,
  Play,
  Plus,
  RefreshCw,
  Router,
  Search,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
  Sun,
  Terminal,
  Trash2,
  UserMinus,
  UserPlus,
  Wifi,
  WifiOff,
  X,
} from 'lucide-react';
import type {
  ConnectedDeviceItem,
  DashboardState,
  DeviceEventPayload,
  NetworkProfile,
  NotificationItem,
  PasswordChangedEventPayload,
  VerificationStepResult,
} from './types';

interface BrowserConnectionInfo {
  effectiveType?: string;
  downlink?: number;
  rtt?: number;
  type?: string;
  online: boolean;
}

export default function App() {
  const [state, setState] = useState<DashboardState | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [isDark, setIsDark] = useState<boolean>(true);

  // Password visibility & copy states
  const [showCurrentPassword, setShowCurrentPassword] = useState<boolean>(true);
  const [showCiphertext, setShowCiphertext] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Live toast/alert banners for real-time password or device events
  const [livePasswordAlert, setLivePasswordAlert] =
    useState<PasswordChangedEventPayload | null>(null);
  const [liveDeviceAlert, setLiveDeviceAlert] =
    useState<DeviceEventPayload | null>(null);

  // Browser Notification permission state
  const [browserNotifPermission, setBrowserNotifPermission] = useState<
    NotificationPermission | 'unsupported'
  >(() => {
    if (typeof window !== 'undefined' && 'Notification' in window) {
      return Notification.permission;
    }
    return 'unsupported';
  });

  // Browser Network Information API state
  const [browserNetInfo, setBrowserNetInfo] = useState<BrowserConnectionInfo>({
    online: typeof navigator !== 'undefined' ? navigator.onLine : true,
  });

  // Filter & search states for Devices, History, and Notifications
  const [deviceFilterMode, setDeviceFilterMode] = useState<
    'active_ssid' | 'live_only' | 'all'
  >('active_ssid');
  const [deviceSearch, setDeviceSearch] = useState<string>('');
  const [historyFilterMode, setHistoryFilterMode] = useState<'active' | 'all'>('all');
  const [historySearch, setHistorySearch] = useState<string>('');
  const [notifCategoryFilter, setNotifCategoryFilter] = useState<
    'all' | 'unread' | 'password_changed' | 'devices' | 'router_connectivity'
  >('all');
  const [revealedHistoryIds, setRevealedHistoryIds] = useState<Record<number, boolean>>(
    {}
  );

  // One-Time Authorized Router Setup Form State
  const [setupOpen, setSetupOpen] = useState<boolean>(false);
  const [setupSsid, setSetupSsid] = useState<string>('');
  const [setupBssid, setSetupBssid] = useState<string>('');
  const [setupBand, setSetupBand] = useState<string>('5 GHz (802.11ax Wi-Fi 6)');
  const [setupSecurity, setSetupSecurity] = useState<string>('WPA2/WPA3-Personal');
  const [setupBrandId, setSetupBrandId] = useState<string>('tplink-archer');
  const [setupGatewayIp, setSetupGatewayIp] = useState<string>('192.168.0.1');
  const [setupRouterIp, setSetupRouterIp] = useState<string>('192.168.0.1');
  const [setupAdminUser, setSetupAdminUser] = useState<string>('admin');
  const [setupAdminPassword, setSetupAdminPassword] = useState<string>('');
  const [setupInitialWifiPassword, setSetupInitialWifiPassword] = useState<string>('');
  const [setupSubmitting, setSetupSubmitting] = useState<boolean>(false);

  // Add / Connect Device Form State
  const [showAddDeviceForm, setShowAddDeviceForm] = useState<boolean>(false);
  const [newDeviceHostname, setNewDeviceHostname] = useState<string>(
    'Galaxy-S26-Ultra'
  );
  const [newDeviceIp, setNewDeviceIp] = useState<string>('192.168.0.154');
  const [newDeviceMac, setNewDeviceMac] = useState<string>('60:AB:67:82:19:C4');
  const [newDeviceActiveAssoc, setNewDeviceActiveAssoc] = useState<boolean>(true);
  const [deviceSubmitting, setDeviceSubmitting] = useState<boolean>(false);

  // Live Router Password Change Test Panel State
  const [testNewPassword, setTestNewPassword] = useState<string>('');
  const [testSubmitting, setTestSubmitting] = useState<boolean>(false);
  const [pollingNow, setPollingNow] = useState<boolean>(false);

  // 10-Step Verification Runner State
  const [verificationResults, setVerificationResults] = useState<
    VerificationStepResult[] | null
  >(null);
  const [runningVerification, setRunningVerification] = useState<boolean>(false);

  // Companion Agent Code Viewer Modal
  const [showCompanionCode, setShowCompanionCode] = useState<boolean>(false);

  // Sync dark mode class on <html>
  useEffect(() => {
    const root = document.documentElement;
    if (isDark) {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
  }, [isDark]);

  // Read Browser Network Information API where permitted
  useEffect(() => {
    const updateBrowserConnection = () => {
      const nav = navigator as Navigator & {
        connection?: {
          effectiveType?: string;
          downlink?: number;
          rtt?: number;
          type?: string;
        };
      };
      const conn = nav.connection;
      setBrowserNetInfo({
        online: navigator.onLine,
        effectiveType: conn?.effectiveType,
        downlink: conn?.downlink,
        rtt: conn?.rtt,
        type: conn?.type,
      });
    };

    updateBrowserConnection();
    window.addEventListener('online', updateBrowserConnection);
    window.addEventListener('offline', updateBrowserConnection);
    return () => {
      window.removeEventListener('online', updateBrowserConnection);
      window.removeEventListener('offline', updateBrowserConnection);
    };
  }, []);

  // Trigger optional Browser Notification
  const triggerBrowserNotification = useCallback((title: string, body: string) => {
    if (
      typeof window !== 'undefined' &&
      'Notification' in window &&
      Notification.permission === 'granted'
    ) {
      try {
        new Notification(title, { body });
      } catch {
        // Ignore environments that block Notification constructor inside iframes
      }
    }
  }, []);

  const fetchDashboardState = useCallback(async () => {
    try {
      const res = await fetch('/api/state');
      if (!res.ok) throw new Error('Failed to load monitoring state');
      const data = (await res.json()) as DashboardState;
      setState(data);
      setLoading(false);
    } catch (err) {
      setErrorMsg(
        err instanceof Error ? err.message : 'Unable to reach monitoring backend.'
      );
      setLoading(false);
    }
  }, []);

  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    fetchDashboardState();

    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let isUnmounted = false;

    const connectWebSocket = () => {
      if (isUnmounted) return;
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws`;
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!isUnmounted) setWsConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'state:init' || msg.type === 'state:sync') {
            setState(msg.payload as DashboardState);
            setLoading(false);
          } else if (msg.type === 'state:heartbeat') {
            setState((prev) => {
              if (!prev) return prev;
              return {
                ...prev,
                companion: msg.payload.companion,
                activeNetwork: msg.payload.activeNetwork || prev.activeNetwork,
                totalConnectedDevices:
                  typeof msg.payload.totalConnectedDevices === 'number'
                    ? msg.payload.totalConnectedDevices
                    : prev.totalConnectedDevices,
                newlyDetectedDevicesCount:
                  typeof msg.payload.newlyDetectedDevicesCount === 'number'
                    ? msg.payload.newlyDetectedDevicesCount
                    : prev.newlyDetectedDevicesCount,
              };
            });
          } else if (msg.type === 'password:changed') {
            const { event: changeEv, state: updatedState } = msg.payload as {
              event: PasswordChangedEventPayload;
              state: DashboardState;
            };
            setState(updatedState);
            setLivePasswordAlert(changeEv);
            triggerBrowserNotification(
              'Wi-Fi Password Changed!',
              `Network: ${changeEv.ssid}\nNew Password: ${changeEv.newPassword}\nChanged: ${changeEv.changeDate} at ${changeEv.changeTime}`
            );
          } else if (msg.type === 'device:event') {
            const { event: devEv, state: updatedState } = msg.payload as {
              event: DeviceEventPayload;
              state: DashboardState;
            };
            setState(updatedState);
            setLiveDeviceAlert(devEv);
            triggerBrowserNotification(
              devEv.title,
              `${devEv.deviceHostname} (${devEv.deviceIp} · ${devEv.deviceMac}) on ${devEv.ssid}`
            );
          }
        } catch {
          // Ignore malformed WS packets
        }
      };

      ws.onclose = () => {
        if (!isUnmounted) {
          setWsConnected(false);
          reconnectTimer = setTimeout(connectWebSocket, 2500);
        }
      };

      ws.onerror = () => {
        ws.close();
      };
    };

    connectWebSocket();

    return () => {
      isUnmounted = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (wsRef.current) wsRef.current.close();
    };
  }, [fetchDashboardState, triggerBrowserNotification]);

  const activeNetwork: NetworkProfile | null = state?.activeNetwork || null;

  // Pre-fill test password suggestion when active network changes
  useEffect(() => {
    if (activeNetwork) {
      const cleanPrefix =
        activeNetwork.ssid.replace(/[^a-zA-Z0-9]/g, '').slice(0, 8) || 'WiFi';
      const randomNum = Math.floor(100 + Math.random() * 900);
      setTestNewPassword(`${cleanPrefix}@Router${randomNum}#Key`);
    }
  }, [activeNetwork?.id, activeNetwork?.currentPassword]);

  const copyToClipboard = async (text: string, keyId: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(keyId);
      setTimeout(() => setCopiedKey(null), 1800);
    } catch {
      // Ignore
    }
  };

  const requestBrowserNotifications = async () => {
    if (typeof window === 'undefined' || !('Notification' in window)) {
      setBrowserNotifPermission('unsupported');
      return;
    }
    try {
      const result = await Notification.requestPermission();
      setBrowserNotifPermission(result);
    } catch {
      setBrowserNotifPermission('denied');
    }
  };

  const handleSelectNetwork = async (networkId: number) => {
    setErrorMsg(null);
    try {
      const res = await fetch('/api/networks/select', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ networkId }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to switch network');
      setState(data as DashboardState);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to switch network');
    }
  };

  const handleToggleMonitoring = async (network: NetworkProfile) => {
    if (!network.isSupported) return;
    setErrorMsg(null);
    try {
      const res = await fetch('/api/networks/toggle-monitoring', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          networkId: network.id,
          enabled: !network.monitoringEnabled,
        }),
      });
      const data = await res.json();
      if (!res.ok)
        throw new Error(data.error || 'Failed to update monitoring status');
      setState(data as DashboardState);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to toggle monitoring');
    }
  };

  const handleToggleRouterConnectivity = async (network: NetworkProfile) => {
    if (!network.isSupported) return;
    setErrorMsg(null);
    const nextStatus = network.connectionStatus === 'OFFLINE' ? 'LIVE' : 'OFFLINE';
    try {
      const res = await fetch('/api/networks/toggle-monitoring', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          networkId: network.id,
          connectionStatus: nextStatus,
        }),
      });
      const data = await res.json();
      if (!res.ok)
        throw new Error(data.error || 'Failed to update router connectivity state');
      setState(data as DashboardState);
    } catch (err) {
      setErrorMsg(
        err instanceof Error ? err.message : 'Failed to toggle connectivity'
      );
    }
  };

  const openSetupForNetwork = (network?: NetworkProfile) => {
    if (network) {
      setSetupSsid(network.ssid);
      setSetupBssid(network.bssid);
      setSetupBand(network.band);
      setSetupSecurity(network.securityType);
      setSetupBrandId(network.routerBrandId);
      setSetupGatewayIp(network.gatewayIp);
      setSetupRouterIp(network.routerIp || network.gatewayIp);
      setSetupAdminUser(network.adminUsername);
      setSetupAdminPassword('');
      setSetupInitialWifiPassword(network.currentPassword || '');
    } else {
      setSetupSsid('');
      setSetupBssid('C0:06:C3:9B:12:44');
      setSetupBand('5 GHz (802.11ax Wi-Fi 6)');
      setSetupSecurity('WPA2/WPA3-Personal');
      setSetupBrandId('tplink-archer');
      setSetupGatewayIp('192.168.0.1');
      setSetupRouterIp('192.168.0.1');
      setSetupAdminUser('admin');
      setSetupAdminPassword('');
      setSetupInitialWifiPassword('');
    }
    setSetupOpen(true);
  };

  const handleBrandSelectionChange = (brandId: string) => {
    setSetupBrandId(brandId);
    const spec = state?.routerBrands.find((b) => b.id === brandId);
    if (spec) {
      setSetupGatewayIp(spec.defaultGateway);
      setSetupRouterIp(spec.defaultGateway);
    }
  };

  const handleSetupSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setSetupSubmitting(true);
    try {
      const res = await fetch('/api/networks/setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ssid: setupSsid,
          bssid: setupBssid,
          band: setupBand,
          securityType: setupSecurity,
          routerBrandId: setupBrandId,
          gatewayIp: setupGatewayIp,
          routerIp: setupRouterIp,
          adminUsername: setupAdminUser,
          adminPassword: setupAdminPassword,
          initialWifiPassword: setupInitialWifiPassword,
          pollIntervalSec: 5,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Router setup failed');
      setState(data as DashboardState);
      setSetupOpen(false);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Router setup failed');
    } finally {
      setSetupSubmitting(false);
    }
  };

  const handleConnectDeviceSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeNetwork) return;
    setErrorMsg(null);
    setDeviceSubmitting(true);
    try {
      const res = await fetch('/api/devices/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          networkId: activeNetwork.id,
          hostname: newDeviceHostname,
          ipAddress: newDeviceIp,
          macAddress: newDeviceMac,
          hasActiveAssociation: newDeviceActiveAssoc,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to register device');
      setState(data.state as DashboardState);
      if (data.event) {
        setLiveDeviceAlert(data.event);
      }
      // Prepare next unique MAC & IP suggestion
      const randOctet = Math.floor(110 + Math.random() * 130);
      const randHex = () =>
        Math.floor(Math.random() * 256)
          .toString(16)
          .padStart(2, '0')
          .toUpperCase();
      setNewDeviceIp(`192.168.0.${randOctet}`);
      setNewDeviceMac(`A4:83:E7:${randHex()}:${randHex()}:${randHex()}`);
      setShowAddDeviceForm(false);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to connect device');
    } finally {
      setDeviceSubmitting(false);
    }
  };

  const handleDisconnectDevice = async (device: ConnectedDeviceItem) => {
    setErrorMsg(null);
    try {
      const res = await fetch('/api/devices/disconnect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ deviceId: device.id }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to disconnect device');
      setState(data.state as DashboardState);
      if (data.event) {
        setLiveDeviceAlert(data.event);
      }
    } catch (err) {
      setErrorMsg(
        err instanceof Error ? err.message : 'Failed to disconnect device'
      );
    }
  };

  const handleReconnectDevice = async (device: ConnectedDeviceItem) => {
    setErrorMsg(null);
    try {
      const res = await fetch('/api/devices/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          networkId: device.networkId,
          hostname: device.hostname,
          ipAddress: device.ipAddress,
          macAddress: device.macAddress,
          hasActiveAssociation: true,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to reconnect device');
      setState(data.state as DashboardState);
      if (data.event) {
        setLiveDeviceAlert(data.event);
      }
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to reconnect device');
    }
  };

  const handleApplyRouterPasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeNetwork) return;
    setErrorMsg(null);
    setTestSubmitting(true);
    try {
      const res = await fetch('/api/router/apply-password-change', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          networkId: activeNetwork.id,
          newRouterPassword: testNewPassword,
          detectImmediately: true,
          sourceLabel: `Authorized Router API (${activeNetwork.routerIp || activeNetwork.gatewayIp})`,
        }),
      });
      const data = await res.json();
      if (!res.ok)
        throw new Error(data.error || 'Failed to update router password');
      setState(data.state as DashboardState);
      if (data.events && data.events.length > 0) {
        setLivePasswordAlert(data.events[0]);
      }
    } catch (err) {
      setErrorMsg(
        err instanceof Error ? err.message : 'Failed to update router password'
      );
    } finally {
      setTestSubmitting(false);
    }
  };

  const handleManualRouterPoll = async () => {
    setPollingNow(true);
    setErrorMsg(null);
    try {
      const res = await fetch('/api/router/poll-now', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Router poll failed');
      setState(data.state as DashboardState);
      if (data.events && data.events.length > 0) {
        setLivePasswordAlert(data.events[0]);
      }
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Router poll failed');
    } finally {
      setTimeout(() => setPollingNow(false), 350);
    }
  };

  const handleRunAllVerificationTests = async () => {
    setRunningVerification(true);
    setErrorMsg(null);
    try {
      const res = await fetch('/api/testing/run-all', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Verification suite failed');
      setVerificationResults(data.results as VerificationStepResult[]);
      setState(data.state as DashboardState);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Verification suite failed');
    } finally {
      setRunningVerification(false);
    }
  };

  const handleMarkNotificationRead = async (
    notificationId?: number,
    markAll = false
  ) => {
    try {
      const res = await fetch('/api/notifications/mark-read', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ notificationId, markAll }),
      });
      if (res.ok) {
        const data = (await res.json()) as DashboardState;
        setState(data);
      }
    } catch {
      // Ignore
    }
  };

  const handleDeleteNetwork = async (networkId: number) => {
    setErrorMsg(null);
    try {
      const res = await fetch(`/api/networks/${networkId}`, {
        method: 'DELETE',
      });
      const data = await res.json();
      if (!res.ok)
        throw new Error(data.error || 'Could not remove network profile');
      setState(data as DashboardState);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Could not remove network');
    }
  };

  const filteredDevices = useMemo(() => {
    if (!state) return [];
    return state.devices.filter((d) => {
      if (
        deviceFilterMode === 'active_ssid' &&
        activeNetwork &&
        d.networkId !== activeNetwork.id
      ) {
        return false;
      }
      if (deviceFilterMode === 'live_only' && d.connectionStatus !== 'LIVE') {
        return false;
      }
      if (deviceSearch.trim()) {
        const q = deviceSearch.toLowerCase();
        return (
          d.hostname.toLowerCase().includes(q) ||
          d.ipAddress.toLowerCase().includes(q) ||
          d.macAddress.toLowerCase().includes(q) ||
          d.manufacturer.toLowerCase().includes(q) ||
          d.ssid.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [state, deviceFilterMode, activeNetwork, deviceSearch]);

  const filteredHistory = useMemo(() => {
    if (!state) return [];
    return state.history.filter((item) => {
      if (
        historyFilterMode === 'active' &&
        activeNetwork &&
        item.networkId !== activeNetwork.id
      ) {
        return false;
      }
      if (historySearch.trim()) {
        const q = historySearch.toLowerCase();
        return (
          item.ssid.toLowerCase().includes(q) ||
          item.newPassword.toLowerCase().includes(q) ||
          item.previousPassword.toLowerCase().includes(q) ||
          item.changeDate.toLowerCase().includes(q) ||
          item.routerBrand.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [state, historyFilterMode, activeNetwork, historySearch]);

  const filteredNotifications = useMemo(() => {
    if (!state) return [];
    return state.notifications.filter((n) => {
      if (notifCategoryFilter === 'unread') return !n.isRead;
      if (notifCategoryFilter === 'password_changed')
        return n.alertType === 'password_changed';
      if (notifCategoryFilter === 'devices')
        return (
          n.alertType === 'device_connected' ||
          n.alertType === 'device_disconnected'
        );
      if (notifCategoryFilter === 'router_connectivity')
        return n.alertType === 'router_connectivity';
      return true;
    });
  }, [state, notifCategoryFilter]);

  const selectedBrandSpec = useMemo(() => {
    return state?.routerBrands.find((b) => b.id === setupBrandId) || null;
  }, [state, setupBrandId]);

  if (loading && !state) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex items-center justify-center p-6">
        <div className="max-w-md w-full border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-xl p-6 space-y-4">
          <div className="flex items-center gap-3">
            <RefreshCw className="w-5 h-5 text-blue-600 dark:text-blue-400 animate-spin" />
            <h1 className="text-base font-semibold">
              Initializing Auto WiFi Password & Device Monitor...
            </h1>
          </div>
          <p className="text-sm text-slate-600 dark:text-slate-400">
            Connecting to AES-256-GCM encrypted SQLite database and real-time router telemetry stream.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex flex-col">
      {/* =====================================================================
          Strict 3-Zone Top Navigation Bar Contract
          Zone 1: Single-line Brand Title
          Zone 2: 5 Single-line Navigation Links
          Zone 3: 1 Primary Action Button
      ===================================================================== */}
      <header className="sticky top-0 z-30 bg-white/95 dark:bg-slate-950/95 backdrop-blur border-b border-slate-200 dark:border-slate-800">
        <div className="max-w-[1440px] mx-auto flex items-center justify-between gap-8 px-6 py-4">
          <a
            href="#dashboard-top"
            className="text-lg font-bold tracking-tight text-slate-900 dark:text-white whitespace-nowrap shrink-0"
          >
            Auto WiFi Password Monitor
          </a>

          <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-600 dark:text-slate-400">
            <a
              href="#live-monitor"
              className="hover:text-slate-900 dark:hover:text-white hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
            >
              Live Telemetry
            </a>
            <a
              href="#connected-devices"
              className="hover:text-slate-900 dark:hover:text-white hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
            >
              Connected Devices ({state?.totalConnectedDevices ?? 0})
            </a>
            <a
              href="#notifications-center"
              className="hover:text-slate-900 dark:hover:text-white hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
            >
              Security Alerts ({state?.unreadCount ?? 0})
            </a>
            <a
              href="#password-history"
              className="hover:text-slate-900 dark:hover:text-white hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
            >
              Password History
            </a>
            <a
              href="#e2e-verification"
              className="hover:text-slate-900 dark:hover:text-white hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
            >
              Verification Suite
            </a>
          </nav>

          <div className="flex items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={() => openSetupForNetwork()}
              className="px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              Configure Wi-Fi Network
            </button>
          </div>
        </div>
      </header>

      {/* =====================================================================
          Main Workspace Container (1440px Desktop Baseline)
      ===================================================================== */}
      <main
        id="dashboard-top"
        className="flex-1 max-w-[1440px] w-full mx-auto px-6 py-8 space-y-8"
      >
        {/* Top Utility & System Telemetry Toolbar */}
        <div className="flex flex-wrap items-center justify-between gap-4 pb-6 border-b border-slate-200 dark:border-slate-800">
          <div className="space-y-1">
            <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900 dark:text-white text-balance">
              Real-Time Wi-Fi Password & Connected Device Monitor
            </h1>
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-600 dark:text-slate-400 font-mono tabular-nums">
              <span>Account-Free Local Dashboard</span>
              <span aria-hidden="true">·</span>
              <span>Storage: SQLite WAL + AES-256-GCM</span>
              <span aria-hidden="true">·</span>
              <span>
                WebSocket Stream: {wsConnected ? 'LIVE (Connected)' : 'Reconnecting'}
              </span>
              <span aria-hidden="true">·</span>
              <span>
                Host Interface: {state?.hostEnvironment.interfaceName || 'eth0'} (
                {state?.hostEnvironment.localIp || 'Local'})
              </span>
              <span aria-hidden="true">·</span>
              <span>
                Worker Cycles: {state?.companion.pollCyclesCompleted ?? 0}
              </span>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <button
              type="button"
              onClick={handleRunAllVerificationTests}
              disabled={runningVerification}
              className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-semibold text-emerald-950 bg-emerald-400 hover:bg-emerald-300 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>
                {runningVerification
                  ? 'Running 10-Step Verification...'
                  : 'Run 10-Step Verification'}
              </span>
            </button>

            <button
              type="button"
              onClick={handleManualRouterPoll}
              disabled={pollingNow}
              className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <RefreshCw
                className={`w-3.5 h-3.5 ${pollingNow ? 'animate-spin text-blue-500' : ''}`}
              />
              <span>Poll Router Now</span>
            </button>

            <button
              type="button"
              onClick={requestBrowserNotifications}
              className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Bell className="w-3.5 h-3.5" />
              <span>
                {browserNotifPermission === 'granted'
                  ? 'Browser Push: ON'
                  : browserNotifPermission === 'denied'
                    ? 'Browser Push: Blocked'
                    : 'Enable Browser Push'}
              </span>
            </button>

            <button
              type="button"
              onClick={() => setIsDark((prev) => !prev)}
              className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              aria-label="Toggle color theme"
            >
              {isDark ? (
                <>
                  <Sun className="w-3.5 h-3.5 text-amber-400" />
                  <span>Light</span>
                </>
              ) : (
                <>
                  <Moon className="w-3.5 h-3.5 text-slate-700" />
                  <span>Dark</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Error feedback banner */}
        {errorMsg && (
          <div className="flex items-center justify-between gap-4 p-4 rounded-xl border border-red-300 dark:border-red-900/80 bg-red-50 dark:bg-red-950/40 text-red-900 dark:text-red-200 text-sm">
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-4 h-4 text-red-600 dark:text-red-400 shrink-0" />
              <span>{errorMsg}</span>
            </div>
            <button
              type="button"
              onClick={() => setErrorMsg(null)}
              className="p-1 text-red-700 dark:text-red-300 hover:opacity-80 cursor-pointer"
              aria-label="Dismiss error"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Real-Time In-Website Password Change Notification Alert */}
        {livePasswordAlert && (
          <section
            aria-live="polite"
            className="rounded-xl border border-emerald-500/50 dark:border-emerald-500/40 bg-emerald-50/90 dark:bg-emerald-950/30 p-6 space-y-4"
          >
            <div className="flex items-start justify-between gap-4">
              <div className="flex items-center gap-2.5">
                <Bell className="w-5 h-5 text-emerald-700 dark:text-emerald-400 shrink-0" />
                <h2 className="text-lg font-bold text-emerald-950 dark:text-emerald-200">
                  Wi-Fi Password Changed!
                </h2>
              </div>
              <button
                type="button"
                onClick={() => setLivePasswordAlert(null)}
                className="px-3 py-1 text-xs font-medium text-emerald-900 dark:text-emerald-200 border border-emerald-400/50 rounded-md hover:bg-emerald-100 dark:hover:bg-emerald-900/50 transition-colors cursor-pointer"
              >
                Dismiss Alert
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 pt-2 border-t border-emerald-200 dark:border-emerald-800/60 text-sm">
              <div>
                <div className="text-xs text-emerald-800 dark:text-emerald-400">
                  Network (SSID)
                </div>
                <div className="font-semibold text-slate-900 dark:text-white mt-0.5 font-mono">
                  {livePasswordAlert.ssid}
                </div>
              </div>
              <div>
                <div className="text-xs text-emerald-800 dark:text-emerald-400">
                  Previous Password
                </div>
                <div className="font-mono tabular-nums text-slate-700 dark:text-slate-300 mt-0.5 break-all">
                  {livePasswordAlert.previousPassword}
                </div>
              </div>
              <div>
                <div className="text-xs text-emerald-800 dark:text-emerald-400">
                  New Password
                </div>
                <div className="flex items-center gap-2 mt-0.5">
                  <span className="font-mono tabular-nums font-bold text-emerald-950 dark:text-emerald-200 break-all">
                    {livePasswordAlert.newPassword}
                  </span>
                  <button
                    type="button"
                    onClick={() =>
                      copyToClipboard(
                        livePasswordAlert.newPassword,
                        'live-alert-pass'
                      )
                    }
                    className="p-1 text-emerald-800 dark:text-emerald-300 hover:opacity-80 cursor-pointer shrink-0"
                    title="Copy new password"
                  >
                    {copiedKey === 'live-alert-pass' ? (
                      <Check className="w-3.5 h-3.5" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>
              </div>
              <div>
                <div className="text-xs text-emerald-800 dark:text-emerald-400">
                  Change Date
                </div>
                <div className="font-mono tabular-nums text-slate-900 dark:text-white mt-0.5">
                  {livePasswordAlert.changeDate}
                </div>
              </div>
              <div>
                <div className="text-xs text-emerald-800 dark:text-emerald-400">
                  Change Time
                </div>
                <div className="font-mono tabular-nums text-slate-900 dark:text-white mt-0.5">
                  {livePasswordAlert.changeTime}
                </div>
              </div>
            </div>
          </section>
        )}

        {/* Real-Time Device Join / Leave Notification Alert */}
        {liveDeviceAlert && (
          <section
            aria-live="polite"
            className="rounded-xl border border-blue-500/50 dark:border-blue-500/40 bg-blue-50/90 dark:bg-blue-950/30 p-5 flex flex-wrap items-center justify-between gap-4"
          >
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-sm font-bold text-blue-950 dark:text-blue-200">
                <Smartphone className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                <span>{liveDeviceAlert.title}</span>
              </div>
              <div className="text-xs font-mono tabular-nums text-slate-700 dark:text-slate-300">
                Network: {liveDeviceAlert.ssid} · Hostname:{' '}
                {liveDeviceAlert.deviceHostname} · IP: {liveDeviceAlert.deviceIp} ·
                MAC: {liveDeviceAlert.deviceMac} · Vendor:{' '}
                {liveDeviceAlert.deviceManufacturer} · {liveDeviceAlert.changeDate}{' '}
                {liveDeviceAlert.changeTime}
              </div>
            </div>
            <button
              type="button"
              onClick={() => setLiveDeviceAlert(null)}
              className="px-3 py-1 text-xs font-medium text-blue-900 dark:text-blue-200 border border-blue-400/50 rounded-md hover:bg-blue-100 dark:hover:bg-blue-900/50 transition-colors cursor-pointer"
            >
              Dismiss
            </button>
          </section>
        )}

        {/* ===================================================================
            Section 5: Real-Time Dashboard Telemetry Grid (8 Comprehensive Cards)
            - Currently Connected Wi-Fi & Actual Wi-Fi Name
            - Router IP & Gateway IP
            - Current Password Retrieval Status & Encrypted Passphrase
            - Total Connected Devices & Newly Detected Devices
            - Router Compatibility Status
            - Last Successful Monitoring Time
            - Last Password Change
            - Real-Time Security Alerts (Unread Count)
        =================================================================== */}
        <section
          id="live-monitor"
          className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4"
        >
          {/* 1. Currently Connected Wi-Fi & Actual SSID */}
          <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-xl p-5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
              <span>Currently Connected Wi-Fi (SSID)</span>
              <Wifi className="w-4 h-4 text-blue-600 dark:text-blue-400" />
            </div>
            <div className="mt-3">
              <div className="text-xl font-bold text-slate-900 dark:text-white truncate font-mono">
                {activeNetwork ? activeNetwork.ssid : 'No Network Selected'}
              </div>
              <div className="text-xs text-slate-500 dark:text-slate-400 mt-1 font-mono tabular-nums">
                {activeNetwork
                  ? `Status: ${activeNetwork.connectionStatus} · BSSID: ${activeNetwork.bssid}`
                  : 'Select or add an authorized router'}
              </div>
            </div>
          </div>

          {/* 2. Router IP & Gateway IP */}
          <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-xl p-5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
              <span>Router IP & Gateway Address</span>
              <Router className="w-4 h-4 text-blue-600 dark:text-blue-400" />
            </div>
            <div className="mt-3">
              <div className="text-xl font-bold font-mono tabular-nums text-slate-900 dark:text-white">
                {activeNetwork
                  ? activeNetwork.routerIp || activeNetwork.gatewayIp
                  : 'Unavailable'}
              </div>
              <div className="text-xs text-slate-500 dark:text-slate-400 mt-1 font-mono tabular-nums">
                {activeNetwork
                  ? `Gateway: ${activeNetwork.gatewayIp} · ${activeNetwork.band}`
                  : 'No active gateway'}
              </div>
            </div>
          </div>

          {/* 3. Current Password Retrieval Status & Passphrase */}
          <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-xl p-5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
              <span>Current Password Retrieval Status</span>
              <KeyRound className="w-4 h-4 text-blue-600 dark:text-blue-400" />
            </div>
            <div className="mt-3">
              {activeNetwork &&
              activeNetwork.isSupported &&
              activeNetwork.connectionStatus === 'LIVE' &&
              activeNetwork.currentPassword ? (
                <>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-base font-bold font-mono tabular-nums text-slate-900 dark:text-white truncate">
                      {showCurrentPassword
                        ? activeNetwork.currentPassword
                        : '••••••••••••••••'}
                    </span>
                    <div className="flex items-center gap-1 shrink-0">
                      <button
                        type="button"
                        onClick={() => setShowCurrentPassword((p) => !p)}
                        className="p-1.5 text-slate-500 hover:text-slate-900 dark:hover:text-white rounded-md cursor-pointer"
                        title={
                          showCurrentPassword ? 'Hide password' : 'Show password'
                        }
                      >
                        {showCurrentPassword ? (
                          <EyeOff className="w-4 h-4" />
                        ) : (
                          <Eye className="w-4 h-4" />
                        )}
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          copyToClipboard(
                            activeNetwork.currentPassword || '',
                            'main-current-pass'
                          )
                        }
                        className="p-1.5 text-slate-500 hover:text-slate-900 dark:hover:text-white rounded-md cursor-pointer"
                        title="Copy current Wi-Fi password"
                      >
                        {copiedKey === 'main-current-pass' ? (
                          <Check className="w-4 h-4 text-emerald-500" />
                        ) : (
                          <Copy className="w-4 h-4" />
                        )}
                      </button>
                    </div>
                  </div>
                  <div className="text-xs text-emerald-600 dark:text-emerald-400 mt-1 flex items-center justify-between">
                    <span>{activeNetwork.passwordRetrievalStatus}</span>
                    <button
                      type="button"
                      onClick={() => setShowCiphertext((c) => !c)}
                      className="underline text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white cursor-pointer"
                    >
                      {showCiphertext ? 'Hide Cipher' : 'AES Proof'}
                    </button>
                  </div>
                  {showCiphertext && activeNetwork.encryptedPreview && (
                    <div className="mt-1.5 text-[11px] font-mono text-slate-500 dark:text-slate-400 break-all">
                      {activeNetwork.encryptedPreview}
                    </div>
                  )}
                </>
              ) : (
                <>
                  <div className="text-sm font-bold text-amber-600 dark:text-amber-400">
                    {activeNetwork?.passwordRetrievalStatus ||
                      'Password Retrieval Unsupported'}
                  </div>
                  <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                    Never guesses, cracks, or fabricates passwords
                  </div>
                </>
              )}
            </div>
          </div>

          {/* 4. Total Connected Devices & Newly Detected Devices */}
          <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-xl p-5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
              <span>Connected Devices (Active 802.11)</span>
              <Laptop className="w-4 h-4 text-blue-600 dark:text-blue-400" />
            </div>
            <div className="mt-3 flex items-baseline justify-between">
              <div>
                <div className="text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-white">
                  {state?.totalConnectedDevices ?? 0}{' '}
                  <span className="text-xs font-sans font-normal text-slate-500">
                    LIVE
                  </span>
                </div>
                <div className="text-xs text-slate-500 dark:text-slate-400 mt-1 font-mono tabular-nums">
                  Newly Detected: {state?.newlyDetectedDevicesCount ?? 0} · Stale DHCP Excluded
                </div>
              </div>
              <a
                href="#connected-devices"
                className="text-xs font-medium text-blue-600 dark:text-blue-400 hover:underline whitespace-nowrap"
              >
                Inspect List
              </a>
            </div>
          </div>

          {/* 5. Router Compatibility Status */}
          <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-xl p-5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
              <span>Router Compatibility Status</span>
              {activeNetwork?.isSupported ? (
                <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
              ) : (
                <ShieldAlert className="w-4 h-4 text-amber-600 dark:text-amber-400" />
              )}
            </div>
            <div className="mt-3">
              <div
                className={`text-base font-bold ${
                  activeNetwork?.isSupported
                    ? 'text-emerald-600 dark:text-emerald-400'
                    : 'text-amber-600 dark:text-amber-400'
                }`}
              >
                {activeNetwork?.routerCompatibilityStatus || 'UNSUPPORTED'}
              </div>
              <div className="text-xs text-slate-500 dark:text-slate-400 mt-1 truncate">
                {activeNetwork?.routerBrandName || 'No router selected'}
              </div>
            </div>
          </div>

          {/* 6. Last Successful Monitoring Time */}
          <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-xl p-5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
              <span>Last Successful Monitoring Time</span>
              <RefreshCw className="w-4 h-4 text-blue-600 dark:text-blue-400" />
            </div>
            <div className="mt-3">
              <div className="text-lg font-bold font-mono tabular-nums text-slate-900 dark:text-white">
                {activeNetwork?.lastCheckedIso
                  ? new Date(activeNetwork.lastCheckedIso).toLocaleTimeString()
                  : 'Not Polled'}
              </div>
              <div className="text-xs text-slate-500 dark:text-slate-400 mt-1 font-mono tabular-nums">
                {activeNetwork?.lastCheckedIso
                  ? `${new Date(activeNetwork.lastCheckedIso).toLocaleDateString()} · Interval ${activeNetwork.pollIntervalSec}s`
                  : 'Awaiting authorized poll'}
              </div>
            </div>
          </div>

          {/* 7. Last Password Change */}
          <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-xl p-5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
              <span>Last Password Change</span>
              <History className="w-4 h-4 text-blue-600 dark:text-blue-400" />
            </div>
            <div className="mt-3">
              {activeNetwork?.lastChangeDate ? (
                <>
                  <div className="text-lg font-bold font-mono tabular-nums text-slate-900 dark:text-white">
                    {activeNetwork.lastChangeDate}
                  </div>
                  <div className="text-xs font-mono tabular-nums text-slate-500 dark:text-slate-400 mt-1">
                    At {activeNetwork.lastChangeTime}
                  </div>
                </>
              ) : (
                <>
                  <div className="text-base font-semibold text-slate-500 dark:text-slate-400">
                    No Changes Recorded
                  </div>
                  <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                    {activeNetwork?.isSupported
                      ? 'Awaiting router key rotation'
                      : 'Password Retrieval Unsupported'}
                  </div>
                </>
              )}
            </div>
          </div>

          {/* 8. Real-Time Security Alerts Count */}
          <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-xl p-5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
              <span>Real-Time Security Alerts</span>
              <Bell className="w-4 h-4 text-blue-600 dark:text-blue-400" />
            </div>
            <div className="mt-3 flex items-baseline justify-between">
              <div>
                <div className="text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-white">
                  {state?.unreadCount ?? 0}{' '}
                  <span className="text-xs font-sans font-normal text-slate-500">
                    Unread
                  </span>
                </div>
                <div className="text-xs text-slate-500 dark:text-slate-400 mt-1 font-mono tabular-nums">
                  Total Saved: {state?.notifications.length ?? 0}
                </div>
              </div>
              {(state?.unreadCount ?? 0) > 0 && (
                <button
                  type="button"
                  onClick={() => handleMarkNotificationRead(undefined, true)}
                  className="text-xs font-medium text-blue-600 dark:text-blue-400 hover:underline cursor-pointer whitespace-nowrap"
                >
                  Mark all read
                </button>
              )}
            </div>
          </div>
        </section>

        {/* ===================================================================
            Section 3: Automatic Connected Device Detection & Station Table
            Displays Hostname, Local IP, MAC Address, Manufacturer (OUI),
            First Connection Time, Last Seen Time, Connection Status, and
            Anti-Stale-DHCP Verification Method.
        =================================================================== */}
        <section
          id="connected-devices"
          className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-xl p-6 space-y-5"
        >
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-bold text-slate-900 dark:text-white">
                Connected Devices on Authorized Router ({activeNetwork?.ssid || 'All'})
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Continuously monitors active 802.11 station associations and ARP reachability. Devices with only old/expired DHCP leases are explicitly marked OFFLINE and never counted as connected.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              {/* Filter Segmented Control */}
              <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg">
                <button
                  type="button"
                  onClick={() => setDeviceFilterMode('active_ssid')}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                    deviceFilterMode === 'active_ssid'
                      ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  Current SSID ({activeNetwork?.ssid || 'None'})
                </button>
                <button
                  type="button"
                  onClick={() => setDeviceFilterMode('live_only')}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                    deviceFilterMode === 'live_only'
                      ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  LIVE Only ({state?.totalConnectedDevices ?? 0})
                </button>
                <button
                  type="button"
                  onClick={() => setDeviceFilterMode('all')}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                    deviceFilterMode === 'all'
                      ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  All History ({state?.devices.length ?? 0})
                </button>
              </div>

              {/* Search Input */}
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={deviceSearch}
                  onChange={(e) => setDeviceSearch(e.target.value)}
                  placeholder="Search hostname, IP, MAC, vendor..."
                  className="pl-8 pr-3 py-1.5 text-xs bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>

              <button
                type="button"
                onClick={() => setShowAddDeviceForm((prev) => !prev)}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <UserPlus className="w-3.5 h-3.5" />
                <span>
                  {showAddDeviceForm ? 'Close Device Form' : 'Connect / Test Device'}
                </span>
              </button>
            </div>
          </div>

          {/* Interactive Connect Device / Test Stale DHCP Form */}
          {showAddDeviceForm && (
            <form
              onSubmit={handleConnectDeviceSubmit}
              className="p-4 rounded-xl border border-blue-500/40 bg-slate-50 dark:bg-slate-950 space-y-4"
            >
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold text-slate-900 dark:text-white">
                  Register / Simulate Wireless Client Association on{' '}
                  <span className="font-mono">{activeNetwork?.ssid}</span>
                </h3>
                <span className="text-[11px] text-slate-500 dark:text-slate-400">
                  Manufacturer is automatically resolved via IEEE OUI MAC prefix
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                <div>
                  <label className="block text-xs text-slate-600 dark:text-slate-400 mb-1">
                    Device Name / Hostname *
                  </label>
                  <input
                    type="text"
                    required
                    value={newDeviceHostname}
                    onChange={(e) => setNewDeviceHostname(e.target.value)}
                    placeholder="e.g., iPhone-16-Pro, MacBook-Air"
                    className="w-full px-3 py-1.5 text-xs font-mono bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white"
                  />
                </div>
                <div>
                  <label className="block text-xs text-slate-600 dark:text-slate-400 mb-1">
                    Local IP Address *
                  </label>
                  <input
                    type="text"
                    required
                    value={newDeviceIp}
                    onChange={(e) => setNewDeviceIp(e.target.value)}
                    placeholder="192.168.0.154"
                    className="w-full px-3 py-1.5 text-xs font-mono tabular-nums bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white"
                  />
                </div>
                <div>
                  <label className="block text-xs text-slate-600 dark:text-slate-400 mb-1">
                    MAC Address (OUI Prefix) *
                  </label>
                  <input
                    type="text"
                    required
                    value={newDeviceMac}
                    onChange={(e) => setNewDeviceMac(e.target.value)}
                    placeholder="60:AB:67:82:19:C4"
                    className="w-full px-3 py-1.5 text-xs font-mono tabular-nums bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white"
                  />
                </div>
                <div>
                  <label className="block text-xs text-slate-600 dark:text-slate-400 mb-1">
                    Router Verification Type
                  </label>
                  <select
                    value={newDeviceActiveAssoc ? 'active' : 'dhcp_only'}
                    onChange={(e) =>
                      setNewDeviceActiveAssoc(e.target.value === 'active')
                    }
                    className="w-full px-3 py-1.5 text-xs bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white"
                  >
                    <option value="active">
                      Active 802.11 Station + ARP (LIVE)
                    </option>
                    <option value="dhcp_only">
                      Old DHCP Record Only (Must Mark OFFLINE)
                    </option>
                  </select>
                </div>
              </div>

              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowAddDeviceForm(false)}
                  className="px-3 py-1.5 text-xs font-medium border border-slate-300 dark:border-slate-700 rounded-lg text-slate-700 dark:text-slate-300 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={deviceSubmitting}
                  className="px-4 py-1.5 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-lg cursor-pointer"
                >
                  {deviceSubmitting
                    ? 'Processing...'
                    : newDeviceActiveAssoc
                      ? 'Connect Device & Broadcast Alert'
                      : 'Record Stale DHCP Entry (Verify Exclusion)'}
                </button>
              </div>
            </form>
          )}

          {/* Connected Devices Data Table */}
          <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-lg">
            <table className="w-full text-left border-collapse text-sm">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 text-xs font-medium text-slate-500 dark:text-slate-400">
                  <th className="py-2.5 px-4">Device Name / Hostname</th>
                  <th className="py-2.5 px-4">Local IP Address</th>
                  <th className="py-2.5 px-4">MAC Address</th>
                  <th className="py-2.5 px-4">Manufacturer</th>
                  <th className="py-2.5 px-4">First Connection Time</th>
                  <th className="py-2.5 px-4">Last Seen Time</th>
                  <th className="py-2.5 px-4">Connection Status</th>
                  <th className="py-2.5 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                {filteredDevices.length === 0 ? (
                  <tr>
                    <td
                      colSpan={8}
                      className="py-8 text-center text-sm text-slate-500 dark:text-slate-400"
                    >
                      No devices match the current filter. Click &quot;Connect / Test Device&quot; to test real-time device join detection.
                    </td>
                  </tr>
                ) : (
                  filteredDevices.map((dev) => (
                    <tr
                      key={dev.id}
                      className="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors"
                    >
                      <td className="py-3 px-4">
                        <div className="font-mono font-semibold text-slate-900 dark:text-white">
                          {dev.hostname}
                          {dev.isNewlyDetected && dev.connectionStatus === 'LIVE' && (
                            <span className="text-[11px] font-sans font-semibold text-blue-600 dark:text-blue-400 ml-2">
                              · New Join
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-500 dark:text-slate-400">
                          SSID: {dev.ssid} · {dev.verificationMethod}
                        </div>
                      </td>
                      <td className="py-3 px-4 font-mono tabular-nums text-slate-800 dark:text-slate-200">
                        {dev.ipAddress}
                      </td>
                      <td className="py-3 px-4 font-mono tabular-nums text-slate-700 dark:text-slate-300">
                        {dev.macAddress}
                      </td>
                      <td className="py-3 px-4 text-xs text-slate-700 dark:text-slate-300">
                        {dev.manufacturer}
                      </td>
                      <td className="py-3 px-4 font-mono tabular-nums text-xs text-slate-600 dark:text-slate-400">
                        {new Date(dev.firstConnectedIso).toLocaleString()}
                      </td>
                      <td className="py-3 px-4 font-mono tabular-nums text-xs text-slate-600 dark:text-slate-400">
                        {new Date(dev.lastSeenIso).toLocaleString()}
                      </td>
                      <td className="py-3 px-4 font-mono text-xs font-semibold">
                        {dev.connectionStatus === 'LIVE' ? (
                          <span className="text-emerald-600 dark:text-emerald-400">
                            LIVE
                          </span>
                        ) : (
                          <span className="text-slate-500 dark:text-slate-400">
                            OFFLINE
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-right whitespace-nowrap">
                        {dev.connectionStatus === 'LIVE' ? (
                          <button
                            type="button"
                            onClick={() => handleDisconnectDevice(dev)}
                            className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 rounded-md hover:bg-red-50 dark:hover:bg-red-950/40 hover:text-red-600 dark:hover:text-red-400 transition-colors cursor-pointer"
                          >
                            <UserMinus className="w-3 h-3" />
                            <span>Disconnect</span>
                          </button>
                        ) : (
                          <button
                            type="button"
                            onClick={() => handleReconnectDevice(dev)}
                            className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 rounded-md hover:bg-emerald-50 dark:hover:bg-emerald-950/40 hover:text-emerald-600 dark:hover:text-emerald-400 transition-colors cursor-pointer"
                          >
                            <UserPlus className="w-3 h-3" />
                            <span>Connect Active</span>
                          </button>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>

        {/* ===================================================================
            2-Column Split:
            Left: Authorized Routers & Multi-SSID Selector
            Right: Active Router Inspector & Live WPA2/WPA3 Password Change Control
        =================================================================== */}
        <section
          id="wifi-setup"
          className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch"
        >
          {/* Left Column (7 cols): Multiple Authorized Routers & Custom SSIDs */}
          <div className="lg:col-span-7 border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-xl p-6 flex flex-col justify-between space-y-6">
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <h2 className="text-lg font-bold text-slate-900 dark:text-white">
                    Authorized Routers & Wi-Fi Networks (Multi-SSID)
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    Supports custom SSIDs and multiple authorized routers. Switching networks generates an instant connectivity event.
                  </p>
                </div>

                <button
                  type="button"
                  onClick={() => openSetupForNetwork()}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Add Authorized Router</span>
                </button>
              </div>

              <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-lg">
                <table className="w-full text-left border-collapse text-sm">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 text-xs font-medium text-slate-500 dark:text-slate-400">
                      <th className="py-2.5 px-3.5">Wi-Fi SSID & BSSID</th>
                      <th className="py-2.5 px-3.5">Router IP & Gateway</th>
                      <th className="py-2.5 px-3.5">Status & Compatibility</th>
                      <th className="py-2.5 px-3.5 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                    {state?.networks.map((net) => {
                      const isSelected = activeNetwork?.id === net.id;
                      return (
                        <tr
                          key={net.id}
                          className={`transition-colors ${
                            isSelected
                              ? 'bg-blue-50/70 dark:bg-blue-950/25'
                              : 'hover:bg-slate-50 dark:hover:bg-slate-800/40'
                          }`}
                        >
                          <td className="py-3 px-3.5">
                            <div className="font-mono font-semibold text-slate-900 dark:text-white flex items-center gap-2">
                              <span>{net.ssid}</span>
                              {isSelected && (
                                <span className="text-[11px] font-sans font-medium text-blue-600 dark:text-blue-400">
                                  · Connected
                                </span>
                              )}
                            </div>
                            <div className="text-xs text-slate-500 dark:text-slate-400 font-mono tabular-nums mt-0.5">
                              BSSID {net.bssid} · {net.band}
                            </div>
                          </td>

                          <td className="py-3 px-3.5">
                            <div className="text-xs font-medium text-slate-800 dark:text-slate-200">
                              {net.routerBrandName}
                            </div>
                            <div className="text-xs font-mono tabular-nums text-slate-500 dark:text-slate-400 mt-0.5">
                              Router IP {net.routerIp} · GW {net.gatewayIp}
                            </div>
                          </td>

                          <td className="py-3 px-3.5">
                            {net.connectionStatus === 'LIVE' ? (
                              <div className="text-xs text-emerald-700 dark:text-emerald-400 font-mono font-semibold">
                                LIVE · {net.monitoringEnabled ? 'Monitoring ON' : 'Paused'}
                              </div>
                            ) : net.connectionStatus === 'OFFLINE' ? (
                              <div className="text-xs text-red-600 dark:text-red-400 font-mono font-semibold">
                                OFFLINE · Unreachable
                              </div>
                            ) : (
                              <div className="text-xs text-amber-600 dark:text-amber-400 font-mono font-semibold">
                                UNSUPPORTED · Password Retrieval Unsupported
                              </div>
                            )}
                            <div className="text-[11px] text-slate-500 dark:text-slate-400 font-mono tabular-nums mt-0.5">
                              {net.securityType} · {net.signalDbm} dBm
                            </div>
                          </td>

                          <td className="py-3 px-3.5 text-right whitespace-nowrap">
                            <div className="inline-flex items-center gap-1.5">
                              {!isSelected && (
                                <button
                                  type="button"
                                  onClick={() => handleSelectNetwork(net.id)}
                                  className="px-2.5 py-1 text-xs font-medium bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 rounded-md hover:opacity-90 transition-opacity cursor-pointer"
                                >
                                  Switch Wi-Fi
                                </button>
                              )}
                              <button
                                type="button"
                                onClick={() => openSetupForNetwork(net)}
                                className="px-2.5 py-1 text-xs font-medium border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 rounded-md hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
                              >
                                Configure
                              </button>
                              {(state?.networks.length ?? 0) > 1 && (
                                <button
                                  type="button"
                                  onClick={() => handleDeleteNetwork(net.id)}
                                  className="p-1 text-slate-400 hover:text-red-600 dark:hover:text-red-400 transition-colors cursor-pointer"
                                  title="Delete network profile"
                                >
                                  <Trash2 className="w-3.5 h-3.5" />
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="pt-4 border-t border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-500 dark:text-slate-400">
              <div className="font-mono tabular-nums">
                Host OS Stack: {state?.hostEnvironment.platform} ·{' '}
                {state?.hostEnvironment.detectionMethod}
              </div>
              <div className="font-mono tabular-nums">
                Browser Link: {browserNetInfo.online ? 'LIVE' : 'OFFLINE'}
                {browserNetInfo.downlink ? ` · ~${browserNetInfo.downlink} Mbps` : ''}
                {browserNetInfo.rtt ? ` · ${browserNetInfo.rtt} ms RTT` : ''}
              </div>
            </div>
          </div>

          {/* Right Column (5 cols): Authorized Router Control & Password Change Detection */}
          <div className="lg:col-span-5 border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-xl p-6 flex flex-col justify-between space-y-6">
            {activeNetwork ? (
              <>
                <div className="space-y-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <h2 className="text-lg font-bold text-slate-900 dark:text-white">
                        Router Management: {activeNetwork.ssid}
                      </h2>
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                        {activeNetwork.routerBrandName}
                      </p>
                    </div>

                    {activeNetwork.isSupported && (
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => handleToggleRouterConnectivity(activeNetwork)}
                          className="px-2.5 py-1.5 text-xs font-medium border border-slate-300 dark:border-slate-700 rounded-lg text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer whitespace-nowrap"
                        >
                          {activeNetwork.connectionStatus === 'OFFLINE'
                            ? 'Set Router LIVE'
                            : 'Simulate OFFLINE'}
                        </button>
                        <button
                          type="button"
                          onClick={() => handleToggleMonitoring(activeNetwork)}
                          className={`px-3 py-1.5 text-xs font-semibold rounded-lg border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                            activeNetwork.monitoringEnabled
                              ? 'border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                              : 'border-emerald-600 bg-emerald-600 text-white hover:bg-emerald-500'
                          }`}
                        >
                          {activeNetwork.monitoringEnabled
                            ? 'Pause Worker'
                            : 'Resume Worker'}
                        </button>
                      </div>
                    )}
                  </div>

                  <div className="p-4 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-2 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500 dark:text-slate-400">
                        Protocol
                      </span>
                      <span className="font-mono text-slate-800 dark:text-slate-200 text-right">
                        {activeNetwork.protocol}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500 dark:text-slate-400">
                        Router IP / Gateway IP
                      </span>
                      <span className="font-mono tabular-nums text-slate-800 dark:text-slate-200">
                        {activeNetwork.routerIp} / {activeNetwork.gatewayIp}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500 dark:text-slate-400">
                        Password Retrieval Status
                      </span>
                      <span
                        className={`font-mono font-semibold ${
                          activeNetwork.isSupported &&
                          activeNetwork.connectionStatus === 'LIVE'
                            ? 'text-emerald-600 dark:text-emerald-400'
                            : 'text-amber-600 dark:text-amber-400'
                        }`}
                      >
                        {activeNetwork.passwordRetrievalStatus}
                      </span>
                    </div>
                    <div className="pt-2 border-t border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 leading-relaxed">
                      {activeNetwork.compatibilityNote}
                    </div>
                  </div>

                  {activeNetwork.isSupported ? (
                    <form
                      onSubmit={handleApplyRouterPasswordChange}
                      className="space-y-3 pt-2 border-t border-slate-200 dark:border-slate-800"
                    >
                      <div className="flex items-center justify-between">
                        <label
                          htmlFor="router-new-pass-input"
                          className="text-xs font-semibold text-slate-800 dark:text-slate-200"
                        >
                          Authorized Router WPA2/WPA3 Password Change
                        </label>
                        <span className="text-[11px] text-slate-500 dark:text-slate-400">
                          AES-256-GCM Encrypted
                        </span>
                      </div>
                      <p className="text-xs text-slate-500 dark:text-slate-400">
                        Apply a new WPA2/WPA3 passphrase on{' '}
                        <span className="font-mono font-semibold text-slate-800 dark:text-slate-200">
                          {activeNetwork.ssid}
                        </span>
                        . The background monitoring worker detects the change, encrypts the credential in SQLite, and pushes a WebSocket alert.
                      </p>
                      <div className="flex flex-col sm:flex-row gap-2">
                        <input
                          id="router-new-pass-input"
                          type="text"
                          value={testNewPassword}
                          onChange={(e) => setTestNewPassword(e.target.value)}
                          placeholder="Enter new WPA2/WPA3 password (min 8 chars)"
                          className="flex-1 px-3 py-2 text-sm font-mono bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                        <button
                          type="submit"
                          disabled={
                            testSubmitting ||
                            activeNetwork.connectionStatus === 'OFFLINE'
                          }
                          className="px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                        >
                          {testSubmitting
                            ? 'Updating...'
                            : 'Change Router Password'}
                        </button>
                      </div>
                    </form>
                  ) : (
                    <div className="p-4 rounded-lg border border-amber-300 dark:border-amber-800/80 bg-amber-50/70 dark:bg-amber-950/30 space-y-2">
                      <div className="flex items-center gap-2 text-sm font-semibold text-amber-900 dark:text-amber-300">
                        <WifiOff className="w-4 h-4 shrink-0" />
                        <span>Password Retrieval Unsupported</span>
                      </div>
                      <p className="text-xs text-amber-800 dark:text-amber-300/90 leading-relaxed">
                        The selected router (<span className="font-mono font-semibold">{activeNetwork.ssid}</span>) does not expose its Wi-Fi password via an authorized management interface. In strict compliance with security requirements, this system never guesses, cracks, bypasses, or invents passwords.
                      </p>
                    </div>
                  )}
                </div>

                <div className="pt-4 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 font-mono tabular-nums">
                  <span>
                    Encryption: {state?.securityInfo.encryptionAlgorithm}
                  </span>
                  <button
                    type="button"
                    onClick={() => openSetupForNetwork(activeNetwork)}
                    className="text-blue-600 dark:text-blue-400 hover:underline font-sans font-medium cursor-pointer"
                  >
                    Edit Router Setup
                  </button>
                </div>
              </>
            ) : null}
          </div>
        </section>

        {/* One-Time Authorized Router Setup Drawer */}
        {setupOpen && (
          <section className="border border-blue-500/40 bg-white dark:bg-slate-900 rounded-xl p-6 space-y-6">
            <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-4">
              <div>
                <h2 className="text-lg font-bold text-slate-900 dark:text-white">
                  Authorized Router & Wi-Fi Network Configuration
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  Configure any custom SSID and authorized router management interface. All credentials are encrypted with AES-256-GCM before being written to SQLite.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setSetupOpen(false)}
                className="p-1.5 text-slate-500 hover:text-slate-900 dark:hover:text-white rounded-lg cursor-pointer"
                aria-label="Close setup form"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleSetupSubmit} className="space-y-5">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                    Wi-Fi Network Name (SSID) *
                  </label>
                  <input
                    type="text"
                    required
                    value={setupSsid}
                    onChange={(e) => setSetupSsid(e.target.value)}
                    placeholder="e.g., Afeez net.net, Home-5G"
                    className="w-full px-3 py-2 text-sm font-mono bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                    Router BSSID (AP MAC)
                  </label>
                  <input
                    type="text"
                    value={setupBssid}
                    onChange={(e) => setSetupBssid(e.target.value)}
                    placeholder="C0:06:C3:8A:44:10"
                    className="w-full px-3 py-2 text-sm font-mono tabular-nums bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                    Router Brand & Protocol *
                  </label>
                  <select
                    value={setupBrandId}
                    onChange={(e) => handleBrandSelectionChange(e.target.value)}
                    className="w-full px-3 py-2 text-sm bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white"
                  >
                    {state?.routerBrands.map((b) => (
                      <option key={b.id} value={b.id}>
                        {b.brand} — {b.modelSeries} (
                        {b.supported ? 'Supported' : 'Password Retrieval Unsupported'})
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                    Band & Security
                  </label>
                  <select
                    value={setupBand}
                    onChange={(e) => setSetupBand(e.target.value)}
                    className="w-full px-3 py-2 text-sm bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white"
                  >
                    <option value="5 GHz (802.11ax Wi-Fi 6)">
                      5 GHz (802.11ax Wi-Fi 6)
                    </option>
                    <option value="2.4 GHz / 5 GHz Dual-Band">
                      2.4 GHz / 5 GHz Dual-Band
                    </option>
                    <option value="6 GHz (Wi-Fi 6E / Wi-Fi 7)">
                      6 GHz (Wi-Fi 6E / Wi-Fi 7)
                    </option>
                    <option value="2.4 GHz (802.11n/ax)">2.4 GHz (802.11n/ax)</option>
                  </select>
                </div>
              </div>

              {selectedBrandSpec && (
                <div
                  className={`p-3.5 rounded-lg border text-xs ${
                    selectedBrandSpec.supported
                      ? 'border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-slate-600 dark:text-slate-300'
                      : 'border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 text-amber-900 dark:text-amber-200'
                  }`}
                >
                  <div className="font-semibold">
                    Protocol: {selectedBrandSpec.protocol} · Auth:{' '}
                    {selectedBrandSpec.authMethod}
                  </div>
                  <div className="mt-1">{selectedBrandSpec.compatibilityNote}</div>
                </div>
              )}

              {selectedBrandSpec?.supported && (
                <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
                  <div>
                    <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                      Gateway IP *
                    </label>
                    <input
                      type="text"
                      required
                      value={setupGatewayIp}
                      onChange={(e) => setSetupGatewayIp(e.target.value)}
                      placeholder="192.168.0.1"
                      className="w-full px-3 py-2 text-sm font-mono tabular-nums bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                      Router Management IP *
                    </label>
                    <input
                      type="text"
                      required
                      value={setupRouterIp}
                      onChange={(e) => setSetupRouterIp(e.target.value)}
                      placeholder="192.168.0.1"
                      className="w-full px-3 py-2 text-sm font-mono tabular-nums bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                      Admin Username *
                    </label>
                    <input
                      type="text"
                      required
                      value={setupAdminUser}
                      onChange={(e) => setSetupAdminUser(e.target.value)}
                      placeholder="admin"
                      className="w-full px-3 py-2 text-sm font-mono bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                      Admin Password / Token *
                    </label>
                    <input
                      type="password"
                      required
                      value={setupAdminPassword}
                      onChange={(e) => setSetupAdminPassword(e.target.value)}
                      placeholder="Enter authorized admin secret"
                      className="w-full px-3 py-2 text-sm font-mono bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                      Current Router Wi-Fi Password
                    </label>
                    <input
                      type="text"
                      value={setupInitialWifiPassword}
                      onChange={(e) => setSetupInitialWifiPassword(e.target.value)}
                      placeholder="Retrieved WPA2/WPA3 passphrase"
                      className="w-full px-3 py-2 text-sm font-mono bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white"
                    />
                  </div>
                </div>
              )}

              <div className="flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setSetupOpen(false)}
                  className="px-4 py-2 text-xs font-medium border border-slate-300 dark:border-slate-700 rounded-lg text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={setupSubmitting}
                  className="px-5 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-lg transition-colors cursor-pointer"
                >
                  {setupSubmitting
                    ? 'Encrypting & Saving...'
                    : 'Authorize & Save Router Profile'}
                </button>
              </div>
            </form>
          </section>
        )}

        {/* ===================================================================
            Section 6: Real-Time Security Alerts & Notifications Center
            Supports Password Changes, New Device Connections, Disconnections,
            and Router Connectivity / SSID Switch Alerts.
        =================================================================== */}
        <section
          id="notifications-center"
          className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-xl p-6 space-y-5"
        >
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-bold text-slate-900 dark:text-white">
                Real-Time Security Alerts & Notification Feed
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Automatic alerts for WPA2/WPA3 password changes, new device connections, device disconnections, and router connectivity events.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <div className="flex flex-wrap items-center gap-1 p-1 bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg">
                <button
                  type="button"
                  onClick={() => setNotifCategoryFilter('all')}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                    notifCategoryFilter === 'all'
                      ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  All ({state?.notifications.length ?? 0})
                </button>
                <button
                  type="button"
                  onClick={() => setNotifCategoryFilter('unread')}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                    notifCategoryFilter === 'unread'
                      ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  Unread ({state?.unreadCount ?? 0})
                </button>
                <button
                  type="button"
                  onClick={() => setNotifCategoryFilter('password_changed')}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                    notifCategoryFilter === 'password_changed'
                      ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  Password Alerts
                </button>
                <button
                  type="button"
                  onClick={() => setNotifCategoryFilter('devices')}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                    notifCategoryFilter === 'devices'
                      ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  Device Joins / Leaves
                </button>
                <button
                  type="button"
                  onClick={() => setNotifCategoryFilter('router_connectivity')}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                    notifCategoryFilter === 'router_connectivity'
                      ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  Router Connectivity
                </button>
              </div>

              {(state?.unreadCount ?? 0) > 0 && (
                <button
                  type="button"
                  onClick={() => handleMarkNotificationRead(undefined, true)}
                  className="px-3 py-2 text-xs font-medium border border-slate-300 dark:border-slate-700 rounded-lg text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors whitespace-nowrap cursor-pointer"
                >
                  Mark All Read
                </button>
              )}
            </div>
          </div>

          {filteredNotifications.length === 0 ? (
            <div className="p-8 text-center border border-dashed border-slate-200 dark:border-slate-800 rounded-lg text-sm text-slate-500 dark:text-slate-400">
              No matching security alerts in this category.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {filteredNotifications.map((notif: NotificationItem) => (
                <div
                  key={notif.id}
                  className={`rounded-xl border p-5 space-y-3 transition-colors ${
                    !notif.isRead
                      ? 'border-blue-500/50 bg-blue-50/40 dark:bg-blue-950/20'
                      : 'border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/50'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="text-sm font-bold text-slate-900 dark:text-white">
                        {notif.title}
                      </div>
                      <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                        {notif.routerBrand} · {notif.changeDate} at {notif.changeTime} ·{' '}
                        {notif.isRead ? 'Read' : 'Unread Alert'}
                      </div>
                    </div>
                    {!notif.isRead && (
                      <button
                        type="button"
                        onClick={() => handleMarkNotificationRead(notif.id, false)}
                        className="px-2.5 py-1 text-xs font-medium text-blue-600 dark:text-blue-400 border border-blue-400/40 rounded-md hover:bg-blue-100/50 dark:hover:bg-blue-900/30 cursor-pointer whitespace-nowrap"
                      >
                        Mark Read
                      </button>
                    )}
                  </div>

                  {notif.alertType === 'password_changed' ? (
                    <div className="grid grid-cols-2 gap-y-2.5 gap-x-4 pt-2 border-t border-slate-200 dark:border-slate-800 text-xs">
                      <div>
                        <span className="text-slate-500 dark:text-slate-400 block">
                          Network:
                        </span>
                        <span className="font-mono font-semibold text-slate-900 dark:text-white">
                          {notif.ssid}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500 dark:text-slate-400 block">
                          Change Date & Time:
                        </span>
                        <span className="font-mono tabular-nums text-slate-900 dark:text-white">
                          {notif.changeDate} · {notif.changeTime}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500 dark:text-slate-400 block">
                          Previous Password:
                        </span>
                        <span className="font-mono tabular-nums text-slate-700 dark:text-slate-300 break-all">
                          {notif.previousPassword}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500 dark:text-slate-400 block">
                          New Password:
                        </span>
                        <div className="flex items-center gap-1.5">
                          <span className="font-mono tabular-nums font-bold text-emerald-700 dark:text-emerald-400 break-all">
                            {notif.newPassword}
                          </span>
                          <button
                            type="button"
                            onClick={() =>
                              copyToClipboard(
                                notif.newPassword,
                                `notif-${notif.id}`
                              )
                            }
                            className="p-0.5 text-slate-500 hover:text-slate-900 dark:hover:text-white cursor-pointer shrink-0"
                            title="Copy password"
                          >
                            {copiedKey === `notif-${notif.id}` ? (
                              <Check className="w-3.5 h-3.5 text-emerald-500" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </div>
                      </div>
                    </div>
                  ) : notif.alertType === 'device_connected' ||
                    notif.alertType === 'device_disconnected' ? (
                    <div className="grid grid-cols-2 gap-y-2 gap-x-4 pt-2 border-t border-slate-200 dark:border-slate-800 text-xs">
                      <div>
                        <span className="text-slate-500 dark:text-slate-400 block">
                          Device Hostname:
                        </span>
                        <span className="font-mono font-semibold text-slate-900 dark:text-white">
                          {notif.deviceHostname}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500 dark:text-slate-400 block">
                          Local IP & MAC:
                        </span>
                        <span className="font-mono tabular-nums text-slate-900 dark:text-white">
                          {notif.deviceIp} · {notif.deviceMac}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500 dark:text-slate-400 block">
                          Manufacturer:
                        </span>
                        <span className="text-slate-800 dark:text-slate-200">
                          {notif.deviceManufacturer}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500 dark:text-slate-400 block">
                          Wi-Fi Network:
                        </span>
                        <span className="font-mono text-slate-800 dark:text-slate-200">
                          {notif.ssid}
                        </span>
                      </div>
                    </div>
                  ) : (
                    <div className="pt-2 border-t border-slate-200 dark:border-slate-800 text-xs text-slate-700 dark:text-slate-300">
                      {notif.message}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </section>

        {/* ===================================================================
            Section 4: Password Change History Table
        =================================================================== */}
        <section
          id="password-history"
          className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-xl p-6 space-y-5"
        >
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-bold text-slate-900 dark:text-white">
                Password Change History
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Audit log of WPA2/WPA3 credential changes with SSID, Previous Password, New Password, Change Date, Change Time, and Detection Status.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg">
                <button
                  type="button"
                  onClick={() => setHistoryFilterMode('all')}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                    historyFilterMode === 'all'
                      ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  All Networks
                </button>
                <button
                  type="button"
                  onClick={() => setHistoryFilterMode('active')}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                    historyFilterMode === 'active'
                      ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  Current SSID ({activeNetwork?.ssid || 'None'})
                </button>
              </div>

              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={historySearch}
                  onChange={(e) => setHistorySearch(e.target.value)}
                  placeholder="Filter by SSID, date, password..."
                  className="pl-8 pr-3 py-1.5 text-xs bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white"
                />
              </div>
            </div>
          </div>

          <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-lg">
            <table className="w-full text-left border-collapse text-sm">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 text-xs font-medium text-slate-500 dark:text-slate-400">
                  <th className="py-2.5 px-4">Wi-Fi SSID</th>
                  <th className="py-2.5 px-4">Previous Password</th>
                  <th className="py-2.5 px-4">New Password</th>
                  <th className="py-2.5 px-4">Change Date</th>
                  <th className="py-2.5 px-4">Change Time</th>
                  <th className="py-2.5 px-4">Detection Status & AES-GCM Cipher</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                {filteredHistory.length === 0 ? (
                  <tr>
                    <td
                      colSpan={6}
                      className="py-8 text-center text-sm text-slate-500 dark:text-slate-400"
                    >
                      No matching password change history records found.
                    </td>
                  </tr>
                ) : (
                  filteredHistory.map((item) => {
                    const isHidden = revealedHistoryIds[item.id] === false;
                    return (
                      <tr
                        key={item.id}
                        className="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors"
                      >
                        <td className="py-3 px-4 font-mono font-semibold text-slate-900 dark:text-white">
                          {item.ssid}
                        </td>
                        <td className="py-3 px-4 font-mono tabular-nums text-slate-600 dark:text-slate-400">
                          {isHidden ? '••••••••••••' : item.previousPassword}
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2">
                            <span className="font-mono tabular-nums font-semibold text-emerald-700 dark:text-emerald-400">
                              {isHidden ? '••••••••••••' : item.newPassword}
                            </span>
                            <button
                              type="button"
                              onClick={() =>
                                setRevealedHistoryIds((prev) => ({
                                  ...prev,
                                  [item.id]: isHidden,
                                }))
                              }
                              className="p-1 text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 cursor-pointer"
                              title={isHidden ? 'Show password' : 'Mask password'}
                            >
                              {isHidden ? (
                                <Eye className="w-3.5 h-3.5" />
                              ) : (
                                <EyeOff className="w-3.5 h-3.5" />
                              )}
                            </button>
                            <button
                              type="button"
                              onClick={() =>
                                copyToClipboard(item.newPassword, `hist-${item.id}`)
                              }
                              className="p-1 text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 cursor-pointer"
                              title="Copy new password"
                            >
                              {copiedKey === `hist-${item.id}` ? (
                                <Check className="w-3.5 h-3.5 text-emerald-500" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                          </div>
                        </td>
                        <td className="py-3 px-4 font-mono tabular-nums text-slate-800 dark:text-slate-200">
                          {item.changeDate}
                        </td>
                        <td className="py-3 px-4 font-mono tabular-nums text-slate-800 dark:text-slate-200">
                          {item.changeTime}
                        </td>
                        <td className="py-3 px-4">
                          <div className="text-xs font-medium text-emerald-700 dark:text-emerald-400">
                            {item.detectionStatus} · {item.detectionSource}
                          </div>
                          <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 mt-0.5 truncate max-w-xs">
                            {item.encryptedRecordPreview}
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </section>

        {/* ===================================================================
            Section 10: Automated 10-Step End-to-End Verification Suite
        =================================================================== */}
        <section
          id="e2e-verification"
          className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-xl p-6 space-y-5"
        >
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-bold text-slate-900 dark:text-white">
                10-Step System Verification & Diagnostic Suite
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Executes all 10 required end-to-end tests against the live backend: SSID detection, mobile device join, new device detection, mobile disconnect, password rotation, encrypted SQLite verification, real-time WebSocket alerts, and persistent WAL history.
              </p>
            </div>

            <button
              type="button"
              onClick={handleRunAllVerificationTests}
              disabled={runningVerification}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>
                {runningVerification
                  ? 'Executing All 10 Tests...'
                  : 'Run Complete 10-Step Verification'}
              </span>
            </button>
          </div>

          {verificationResults ? (
            <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-lg">
              <table className="w-full text-left border-collapse text-sm">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 text-xs font-medium text-slate-500 dark:text-slate-400">
                    <th className="py-2.5 px-4">Step</th>
                    <th className="py-2.5 px-4">Verification Requirement</th>
                    <th className="py-2.5 px-4">Result</th>
                    <th className="py-2.5 px-4">Live System & Database Evidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                  {verificationResults.map((r) => (
                    <tr key={r.step}>
                      <td className="py-2.5 px-4 font-mono tabular-nums font-semibold text-slate-700 dark:text-slate-300">
                        0{r.step}
                      </td>
                      <td className="py-2.5 px-4 font-medium text-slate-900 dark:text-white">
                        {r.name}
                      </td>
                      <td className="py-2.5 px-4 font-mono text-xs font-bold">
                        {r.status === 'PASSED' ? (
                          <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            <span>PASSED</span>
                          </span>
                        ) : (
                          <span className="text-red-600 dark:text-red-400">
                            FAILED
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-4 font-mono text-xs text-slate-600 dark:text-slate-300">
                        {r.verificationDetail}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="p-6 rounded-lg border border-dashed border-slate-200 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400 flex items-center justify-between">
              <span>
                Click &quot;Run Complete 10-Step Verification&quot; to execute all 10 integration tests and inspect the cryptographic & database assertions.
              </span>
              <span className="font-mono">10 / 10 Automated Checks Ready</span>
            </div>
          )}
        </section>

        {/* ===================================================================
            Section 7: Local Python FastAPI Companion Agent & Authenticated API
        =================================================================== */}
        <section
          id="companion-agent"
          className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-xl p-6 space-y-5"
        >
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="max-w-3xl space-y-1">
              <h2 className="text-lg font-bold text-slate-900 dark:text-white">
                Local Python Companion Agent v2.0 (FastAPI + Windows netsh / Linux nmcli)
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                Upgraded <span className="font-mono">companion_agent.py</span> uses FastAPI, AES-256-GCM encryption, and authenticated endpoints (<span className="font-mono">X-Companion-Token</span>) to detect OS Wi-Fi networks via Windows <span className="font-mono">netsh wlan</span> and Linux <span className="font-mono">nmcli</span>, verify active 802.11 station associations against DHCP leases, and sync with this dashboard.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2.5 shrink-0">
              <button
                type="button"
                onClick={() => setShowCompanionCode((prev) => !prev)}
                className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium border border-slate-300 dark:border-slate-700 rounded-lg text-slate-800 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
              >
                <Terminal className="w-3.5 h-3.5" />
                <span>
                  {showCompanionCode ? 'Hide CLI & Token' : 'View Companion Token & CLI'}
                </span>
              </button>

              <a
                href="/companion_agent.py"
                download="companion_agent.py"
                className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-slate-900 dark:bg-blue-600 hover:opacity-90 rounded-lg transition-opacity"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download companion_agent.py</span>
              </a>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
            <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 space-y-1.5">
              <div className="flex items-center gap-2 text-xs font-semibold text-slate-900 dark:text-white">
                <Network className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                <span>Windows netsh & Linux nmcli</span>
              </div>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                Automatically detects the currently connected SSID, BSSID, signal strength, and default gateway IP directly from the operating system.
              </p>
            </div>

            <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 space-y-1.5">
              <div className="flex items-center gap-2 text-xs font-semibold text-slate-900 dark:text-white">
                <Router className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                <span>Active Station & DHCP Cross-Check</span>
              </div>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                Verifies active wireless station associations (<span className="font-mono">iwinfo</span> / registration-table / ARP) so expired DHCP records are never reported as connected.
              </p>
            </div>

            <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 space-y-1.5">
              <div className="flex items-center gap-2 text-xs font-semibold text-slate-900 dark:text-white">
                <Lock className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                <span>AES-256-GCM + Token Auth + Rate Limiting</span>
              </div>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                Protects all companion sync requests with <span className="font-mono">X-Companion-Token</span> header authentication, sliding-window rate limiting, and zero plaintext logs.
              </p>
            </div>
          </div>

          {showCompanionCode && (
            <div className="p-4 rounded-lg bg-slate-900 text-slate-100 font-mono text-xs space-y-2 overflow-x-auto border border-slate-800">
              <div className="flex items-center justify-between text-slate-400">
                <span># Authenticated Companion API Token (X-Companion-Token):</span>
                <button
                  type="button"
                  onClick={() =>
                    copyToClipboard(
                      state?.securityInfo.companionApiToken || '',
                      'comp-token'
                    )
                  }
                  className="text-blue-400 hover:underline cursor-pointer"
                >
                  {copiedKey === 'comp-token' ? 'Copied Token!' : 'Copy Token'}
                </button>
              </div>
              <div className="text-emerald-400">
                export COMPANION_API_TOKEN=&quot;{state?.securityInfo.companionApiToken}&quot;
              </div>
              <div className="text-slate-400 pt-2">
                # Run local FastAPI companion agent with authenticated sync:
              </div>
              <div>pip install fastapi uvicorn httpx cryptography pydantic</div>
              <div>
                python companion_agent.py --port 8765 --dashboard-url {window.location.origin}
              </div>
            </div>
          )}
        </section>
      </main>

      {/* Quiet Footer */}
      <footer className="border-t border-slate-200 dark:border-slate-800 py-5 px-6 text-xs text-slate-500 dark:text-slate-400">
        <div className="max-w-[1440px] mx-auto flex flex-wrap items-center justify-between gap-4">
          <span>
            Auto WiFi Password & Device Monitor — Advanced Edition · Account-Free Local Installation
          </span>
          <span>
            AES-256-GCM Encrypted SQLite · Active 802.11 Station Verification · Real-Time WebSockets
          </span>
        </div>
      </footer>
    </div>
  );
}
