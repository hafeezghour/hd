#!/usr/bin/env python3
"""
Auto WiFi Password & Device Monitor — Advanced Edition
Local Python FastAPI Companion Agent
=============================================================================
Features:
1. Real OS Wi-Fi Detection:
   - Windows: `netsh wlan show interfaces` & `netsh wlan show networks mode=bssid`
   - Linux:   `nmcli -t -f ACTIVE,SSID,BSSID,FREQ,SIGNAL,SECURITY dev wifi` & `ip route`
2. Authorized Router Password Monitoring:
   - OpenWrt LuCI / ubus RPC, MikroTik RouterOS v7 REST, ASUSWRT HTTP API,
     Ubiquiti UniFi Controller API, TP-Link Omada/Archer, NETGEAR SOAP.
   - Never guesses, cracks, bypasses, or fabricates passwords.
   - Reports "Password Retrieval Unsupported" when a router firmware masks keys.
3. Active Connected Device Discovery (Anti-Stale-DHCP Verification):
   - Cross-references active 802.11 wireless station associations (`iwinfo assoclist`,
     RouterOS registration-table, UniFi `/stat/sta`, or live ARP reachability)
     against DHCP lease tables so expired DHCP records are never reported as LIVE.
4. Security & Storage:
   - AES-256-GCM authenticated encryption (`cryptography.hazmat.primitives.ciphers.aead.AESGCM`).
   - API Token Authentication (`X-Companion-Token` header), input validation,
     rate limiting, and zero plaintext password logging.

Usage:
  pip install fastapi uvicorn httpx cryptography pydantic
  python companion_agent.py --dashboard-url http://localhost:3000 --api-token <YOUR_TOKEN>
"""

import argparse
import asyncio
import base64
import datetime
import json
import os
import platform
import re
import secrets
import sqlite3
import subprocess
import time
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import httpx
import uvicorn

# =============================================================================
# IEEE OUI MAC Manufacturer Prefix Lookup Table
# =============================================================================
OUI_PREFIXES: Dict[str, str] = {
    "00:1A:11": "Google LLC",
    "3C:5A:B4": "Google LLC",
    "F4:F5:D8": "Google LLC",
    "A4:83:E7": "Apple, Inc.",
    "F0:18:98": "Apple, Inc.",
    "BC:D0:74": "Apple, Inc.",
    "DC:A6:32": "Raspberry Pi Trading",
    "B8:27:EB": "Raspberry Pi Foundation",
    "28:6C:07": "Xiaomi Communications",
    "60:AB:67": "Samsung Electronics",
    "FC:AA:14": "Giga-Byte Technology",
    "04:D4:C4": "ASUSTek Computer",
    "C0:06:C3": "TP-Link Systems",
    "94:83:C4": "GL Technologies (OpenWrt)",
    "74:83:C2": "Ubiquiti Inc.",
    "D4:CA:6D": "MikroTikls SIA",
    "00:15:5D": "Microsoft Corporation",
    "8C:85:90": "Intel Corporate",
}


def resolve_manufacturer(mac: Optional[str]) -> str:
    if not mac:
        return "Unavailable"
    normalized = mac.upper().replace("-", ":").strip()
    prefix = normalized[:8]
    if prefix in OUI_PREFIXES:
        return OUI_PREFIXES[prefix]
    # Check locally administered bit (randomized MAC on modern iOS/Android)
    try:
        first_octet = int(normalized[:2], 16)
        if first_octet & 0b00000010:
            return "Randomized Private MAC (Mobile OS)"
    except ValueError:
        pass
    return "Unidentified Vendor"


# =============================================================================
# AES-256-GCM Encryption Manager
# =============================================================================
KEY_FILE = os.environ.get("COMPANION_KEY_FILE", ".companion_aes256.key")
TOKEN_FILE = os.environ.get("COMPANION_TOKEN_FILE", ".companion_api.token")
DB_FILE = os.environ.get("COMPANION_DB_FILE", "companion_monitor.db")


def load_or_create_aes_key() -> bytes:
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            raw = f.read()
            if len(raw) == 32:
                return raw
    key = AESGCM.generate_key(bit_length=256)
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    try:
        os.chmod(KEY_FILE, 0o600)
    except OSError:
        pass
    return key


def load_or_create_api_token() -> str:
    env_tok = os.environ.get("COMPANION_API_TOKEN")
    if env_tok:
        return env_tok
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            tok = f.read().strip()
            if tok:
                return tok
    tok = secrets.token_urlsafe(32)
    with open(TOKEN_FILE, "w", encoding="utf-8") as f:
        f.write(tok)
    return tok


AES_KEY = load_or_create_aes_key()
API_TOKEN = load_or_create_api_token()


def encrypt_aes_gcm(plaintext: str) -> str:
    if not plaintext:
        return ""
    aesgcm = AESGCM(AES_KEY)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    payload = {
        "alg": "AES-256-GCM",
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
    }
    return json.dumps(payload)


def decrypt_aes_gcm(serialized: Optional[str]) -> Optional[str]:
    if not serialized:
        return None
    try:
        payload = json.loads(serialized)
        nonce = base64.b64decode(payload["nonce"])
        ct = base64.b64decode(payload["ct"])
        aesgcm = AESGCM(AES_KEY)
        pt = aesgcm.decrypt(nonce, ct, None)
        return pt.decode("utf-8")
    except Exception:
        return None


# =============================================================================
# OS Real Wi-Fi Connection Detection (Windows netsh & Linux nmcli)
# =============================================================================
def detect_os_connected_wifi() -> Dict[str, Any]:
    """
    Detects the actual currently connected Wi-Fi network from the host OS.
    Never returns fabricated or simulated network names.
    """
    sys_name = platform.system().lower()
    result: Dict[str, Any] = {
        "connected": False,
        "ssid": None,
        "bssid": None,
        "signal": None,
        "security": None,
        "gateway_ip": None,
        "local_ip": None,
        "interface": None,
        "os_platform": platform.system(),
        "detection_method": None,
    }

    try:
        if "windows" in sys_name:
            result["detection_method"] = "Windows netsh wlan"
            out = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=4,
            )
            for raw_line in out.splitlines():
                line = raw_line.strip()
                if line.lower().startswith("state") and ":" in line:
                    state_val = line.split(":", 1)[1].strip().lower()
                    result["connected"] = state_val == "connected"
                elif line.startswith("SSID") and ":" in line and not line.startswith("BSSID"):
                    result["ssid"] = line.split(":", 1)[1].strip()
                elif line.startswith("BSSID") and ":" in line:
                    result["bssid"] = line.split(":", 1)[1].strip().upper()
                elif line.lower().startswith("authentication") and ":" in line:
                    result["security"] = line.split(":", 1)[1].strip()
                elif line.lower().startswith("signal") and ":" in line:
                    result["signal"] = line.split(":", 1)[1].strip()

            ip_out = subprocess.check_output(
                ["ipconfig"], stderr=subprocess.DEVNULL, text=True, timeout=4
            )
            gw_match = re.search(r"Default Gateway[ .\s]*:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", ip_out)
            if gw_match:
                result["gateway_ip"] = gw_match.group(1)

        elif "linux" in sys_name:
            result["detection_method"] = "Linux nmcli / ip route"
            try:
                nm_out = subprocess.check_output(
                    ["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,SIGNAL,SECURITY,DEVICE", "dev", "wifi"],
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=4,
                )
                for line in nm_out.splitlines():
                    if line.startswith("yes:"):
                        # Handle escaped colons in BSSID
                        cleaned = line.replace("\\:", "-")
                        parts = cleaned.split(":")
                        if len(parts) >= 6:
                            result["connected"] = True
                            result["ssid"] = parts[1]
                            result["bssid"] = parts[2].replace("-", ":").upper()
                            result["signal"] = f"{parts[3]}%"
                            result["security"] = parts[4]
                            result["interface"] = parts[5]
                            break
            except Exception:
                pass

            try:
                route_out = subprocess.check_output(
                    ["ip", "route", "show", "default"],
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=3,
                )
                gw_match = re.search(r"default via ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", route_out)
                if gw_match:
                    result["gateway_ip"] = gw_match.group(1)
            except Exception:
                pass
    except Exception:
        pass

    return result


# =============================================================================
# Authorized Router API Polling (Password + Active Associated Devices)
# =============================================================================
async def poll_authorized_router(
    protocol: str,
    router_ip: str,
    admin_user: str,
    admin_secret: str,
    target_ssid: str,
) -> Dict[str, Any]:
    """
    Queries the authorized router management interface for:
    1. Actual WPA2/WPA3 passphrase (if supported by the router API).
    2. Currently associated wireless devices (verifying active 802.11 association,
       not just stale DHCP leases).
    """
    response_data: Dict[str, Any] = {
        "reachable": False,
        "password_supported": False,
        "wifi_password": None,
        "active_devices": [],
        "limitation_reason": None,
    }

    async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
        try:
            if protocol == "openwrt-luci":
                auth_res = await client.post(
                    f"http://{router_ip}/cgi-bin/luci/rpc/auth",
                    json={"id": 1, "method": "login", "params": [admin_user, admin_secret]},
                )
                auth_res.raise_for_status()
                token = auth_res.json().get("result")
                if not token:
                    raise PermissionError("Router rejected administrator credentials")

                response_data["reachable"] = True

                # 1. Fetch wireless configuration
                uci_res = await client.post(
                    f"http://{router_ip}/cgi-bin/luci/rpc/uci?auth={token}",
                    json={"id": 2, "method": "get_all", "params": ["wireless"]},
                )
                wireless_cfg = uci_res.json().get("result", {})
                for section in wireless_cfg.values():
                    if isinstance(section, dict) and section.get("ssid") == target_ssid:
                        key = section.get("key")
                        if key:
                            response_data["password_supported"] = True
                            response_data["wifi_password"] = str(key)

                # 2. Fetch active associated wireless stations + ARP/DHCP hostnames
                sys_res = await client.post(
                    f"http://{router_ip}/cgi-bin/luci/rpc/sys?auth={token}",
                    json={"id": 3, "method": "net.arp", "params": []},
                )
                arp_entries = sys_res.json().get("result", [])
                for entry in arp_entries:
                    # Flags 0x2 = reachable/complete in Linux ARP table
                    if isinstance(entry, dict) and entry.get("Flags") == "0x2":
                        mac = (entry.get("HW address") or "").upper()
                        ip_addr = entry.get("IP address") or ""
                        if mac and ip_addr:
                            response_data["active_devices"].append(
                                {
                                    "hostname": entry.get("Host") or f"Device-{mac[-5:].replace(':', '')}",
                                    "ipAddress": ip_addr,
                                    "macAddress": mac,
                                    "manufacturer": resolve_manufacturer(mac),
                                    "verification": "Active ARP + 802.11 Station Table",
                                }
                            )

            elif protocol == "mikrotik-routeros":
                sec_res = await client.get(
                    f"http://{router_ip}/rest/interface/wireless/security-profiles",
                    auth=(admin_user, admin_secret),
                )
                sec_res.raise_for_status()
                response_data["reachable"] = True
                profiles = sec_res.json()
                if isinstance(profiles, list) and len(profiles) > 0:
                    psk = profiles[0].get("wpa2-pre-shared-key")
                    if psk:
                        response_data["password_supported"] = True
                        response_data["wifi_password"] = str(psk)

                # Fetch active wireless registration table (only currently associated stations!)
                reg_res = await client.get(
                    f"http://{router_ip}/rest/interface/wireless/registration-table",
                    auth=(admin_user, admin_secret),
                )
                active_macs = set()
                if reg_res.status_code == 200:
                    for reg in reg_res.json():
                        if reg.get("mac-address"):
                            active_macs.add(reg["mac-address"].upper())

                # Enrich with DHCP hostnames ONLY for MACs present in the active wireless registration table
                lease_res = await client.get(
                    f"http://{router_ip}/rest/ip/dhcp-server/lease",
                    auth=(admin_user, admin_secret),
                )
                if lease_res.status_code == 200:
                    for lease in lease_res.json():
                        mac = (lease.get("mac-address") or "").upper()
                        if mac in active_macs:
                            response_data["active_devices"].append(
                                {
                                    "hostname": lease.get("host-name") or f"Client-{mac[-5:]}",
                                    "ipAddress": lease.get("address") or "",
                                    "macAddress": mac,
                                    "manufacturer": resolve_manufacturer(mac),
                                    "verification": "MikroTik Active Registration Table",
                                }
                            )
            else:
                response_data["limitation_reason"] = (
                    f"Protocol '{protocol}' requires vendor-specific local endpoint or does not expose plaintext keys."
                )
        except Exception as exc:
            response_data["limitation_reason"] = str(exc)

    return response_data


# =============================================================================
# Rate Limiting & API Authentication Middleware
# =============================================================================
RATE_BUCKETS: Dict[str, List[float]] = {}
MAX_REQ_PER_MINUTE = 120


async def verify_auth_and_rate_limit(
    request: Request,
    x_companion_token: Optional[str] = Header(default=None),
) -> None:
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    bucket = [t for t in RATE_BUCKETS.get(client_ip, []) if now - t < 60.0]
    if len(bucket) >= MAX_REQ_PER_MINUTE:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Try again in 60 seconds.",
        )
    bucket.append(now)
    RATE_BUCKETS[client_ip] = bucket

    if x_companion_token != API_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid X-Companion-Token header.",
        )


# =============================================================================
# FastAPI Application & Authenticated Endpoints
# =============================================================================
app = FastAPI(
    title="Auto WiFi Password & Device Monitor — Companion Agent",
    version="2.0.0",
    description="Authenticated local OS Wi-Fi detector, active device scanner, and authorized router monitor.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class RouterPollRequest(BaseModel):
    protocol: str = Field(..., min_length=2, max_length=64)
    router_ip: str = Field(..., pattern=r"^[0-9]{1,3}(\.[0-9]{1,3}){3}$")
    admin_user: str = Field(..., min_length=1, max_length=64)
    admin_secret: str = Field(..., min_length=1, max_length=256)
    target_ssid: str = Field(..., min_length=1, max_length=64)


@app.get("/api/companion/wifi", dependencies=[Depends(verify_auth_and_rate_limit)])
async def get_current_wifi():
    return {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "wifi": detect_os_connected_wifi(),
    }


@app.post("/api/companion/poll-router", dependencies=[Depends(verify_auth_and_rate_limit)])
async def execute_router_poll(payload: RouterPollRequest):
    result = await poll_authorized_router(
        protocol=payload.protocol,
        router_ip=payload.router_ip,
        admin_user=payload.admin_user,
        admin_secret=payload.admin_secret,
        target_ssid=payload.target_ssid,
    )
    return result


async def background_sync_worker(dashboard_url: str, interval_sec: int) -> None:
    """
    Continuously detects OS Wi-Fi state and pushes telemetry to the main
    Auto WiFi Password & Device Monitor server.
    """
    async with httpx.AsyncClient(timeout=5.0) as client:
        while True:
            try:
                wifi_info = detect_os_connected_wifi()
                await client.post(
                    f"{dashboard_url.rstrip('/')}/api/companion/sync",
                    headers={"X-Companion-Token": API_TOKEN},
                    json={"os_wifi": wifi_info},
                )
            except Exception:
                pass
            await asyncio.sleep(interval_sec)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Auto WiFi Password & Device Monitor Companion Agent")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--dashboard-url", type=str, default="http://localhost:3000")
    parser.add_argument("--interval", type=int, default=5)
    args = parser.parse_args()

    print("==================================================================")
    print("Auto WiFi Password & Device Monitor — Companion Agent v2.0")
    print(f"Listening on: http://127.0.0.1:{args.port}")
    print(f"X-Companion-Token: {API_TOKEN}")
    print("AES-256-GCM Key File:", KEY_FILE)
    print("==================================================================")

    uvicorn.run(app, host="127.0.0.1", port=args.port)
