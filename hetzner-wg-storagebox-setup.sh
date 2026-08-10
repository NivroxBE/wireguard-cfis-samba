#!/usr/bin/env bash
#
# Hetzner VPS relay: WireGuard (via wg-easy) + Hetzner Storage Box mounted
# over CIFS and re-shared via Samba bound ONLY to the WireGuard interface.
#
# Usage (run as root on a fresh Debian/Ubuntu Hetzner VPS):
#
#   IMPORTANT: download the script to a file and run it, do NOT pipe it
#   straight into bash (`curl ... | bash`). This script prompts for
#   credentials interactively; when piped, stdin is consumed by the
#   download itself and every `read` prompt gets no input, which makes
#   the script hang or silently fail partway through.
#
#   Public repo:
#     curl -fsSL -o setup.sh https://raw.githubusercontent.com/NivroxBE/wireguard-cfis-samba/main/hetzner-wg-storagebox-setup.sh
#     bash setup.sh
#
#   Private repo (raw URLs need auth - GitHub 404s otherwise):
#     Generate a short-lived, repo-scoped, read-only fine-grained PAT at
#     https://github.com/settings/tokens, then:
#       curl -fsSL -H "Authorization: token <PAT>" \
#         -o setup.sh https://raw.githubusercontent.com/NivroxBE/wireguard-cfis-samba/main/hetzner-wg-storagebox-setup.sh
#       bash setup.sh
#     Revoke the PAT once the run finishes.
#
#     Alternative via gh CLI (if installed on the VPS):
#       gh auth login
#       gh api repos/NivroxBE/wireguard-cfis-samba/contents/hetzner-wg-storagebox-setup.sh \
#         --jq '.content' | base64 -d > setup.sh
#       bash setup.sh
#
# Security model:
#   - Only SSH and the WireGuard UDP port are ever exposed publicly.
#   - The wg-easy admin web UI is bound to 127.0.0.1 only - reach it via
#     `ssh -L 51821:127.0.0.1:51821 root@<this-vps>` from your management host.
#   - Samba binds only to the wg0 interface (bind interfaces only = yes),
#     so it is unreachable even from the VPS's public NIC.
#   - You must ALSO lock the Storage Box's own access list (Hetzner Robot
#     panel -> Storage Box -> Access -> Samba/CIFS) to this VPS's public IP.
#     That step cannot be automated from here.
#
# Re-running this script is safe (idempotent where practical).

set -euo pipefail

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: this script must be run as root (use sudo -i or curl | bash as root)." >&2
  exit 1
fi

if ! [[ -f /etc/debian_version ]]; then
  echo "ERROR: this script only supports Debian/Ubuntu." >&2
  exit 1
fi

if [[ ! -t 0 ]]; then
  echo "ERROR: stdin is not an interactive terminal, so the credential prompts below" >&2
  echo "cannot receive input and the script will hang. This happens in some web-based" >&2
  echo "terminals (e.g. proxied/websocket terminals) that don't attach a real tty to" >&2
  echo "the shell session. Try running this over a plain SSH session instead:" >&2
  echo "  ssh root@<this-vps-ip>" >&2
  echo "then re-run: bash setup.sh" >&2
  exit 1
fi

log() { printf '\n\033[1;32m==>\033[0m %s\n' "$1"; }
warn() { printf '\n\033[1;33m!!\033[0m %s\n' "$1" >&2; }

WG_IFACE="wg0"
WG_PORT="51820"
WG_UI_PORT="51821"
WG_SUBNET="10.8.0.0/24"
WG_HOST_ADDR="10.8.0.1"
STORAGEBOX_MOUNT="/mnt/storagebox"
SAMBA_SHARE_NAME="storagebox"
SAMBA_SYSTEM_USER="vpnshare"
CREDENTIALS_FILE="/etc/samba/credentials-storagebox"

log "VPS network details"

read -r -p "This VPS's public IP (used as WireGuard's WG_HOST): " PUBLIC_IP
if [[ -z "${PUBLIC_IP}" ]]; then
  echo "ERROR: public IP is required." >&2
  exit 1
fi

read -r -p "SSH port to keep open in the firewall [22]: " SSH_PORT
SSH_PORT="${SSH_PORT:-22}"

# ---------------------------------------------------------------------------
# Interactive secrets (never logged, never written into this script/repo)
# ---------------------------------------------------------------------------

log "Collecting Storage Box and wg-easy credentials (input hidden)"

read -r -p "Storage Box hostname (e.g. u123456.your-storagebox.de): " STORAGEBOX_HOST
if [[ -z "${STORAGEBOX_HOST}" ]]; then
  echo "ERROR: Storage Box hostname is required." >&2
  exit 1
fi

read -r -p "Storage Box username (e.g. u123456): " STORAGEBOX_USER
if [[ -z "${STORAGEBOX_USER}" ]]; then
  echo "ERROR: Storage Box username is required." >&2
  exit 1
fi

read -r -s -p "Storage Box password: " STORAGEBOX_PASS
echo
if [[ -z "${STORAGEBOX_PASS}" ]]; then
  echo "ERROR: Storage Box password is required." >&2
  exit 1
fi

read -r -s -p "wg-easy admin UI password (for peer management): " WG_EASY_PASSWORD
echo
if [[ -z "${WG_EASY_PASSWORD}" ]]; then
  echo "ERROR: wg-easy admin password is required." >&2
  exit 1
fi

read -r -s -p "Samba share password for VPN clients (leave blank to auto-generate): " SMB_SHARE_PASS
echo
if [[ -z "${SMB_SHARE_PASS}" ]]; then
  SMB_SHARE_PASS="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24)" || true
  echo "  Generated Samba share password: ${SMB_SHARE_PASS}"
  echo "  (save this now - it will also be printed in the final summary)"
fi

# ---------------------------------------------------------------------------
# Base packages
# ---------------------------------------------------------------------------

log "Updating apt and installing base packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl gnupg ufw cifs-utils samba

# ---------------------------------------------------------------------------
# Docker (official apt repo, per Docker's documented install method)
# ---------------------------------------------------------------------------

if ! command -v docker >/dev/null 2>&1; then
  log "Installing Docker Engine from Docker's official apt repository"
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  DISTRO_ID="$(. /etc/os-release && echo "${ID}")"
  DISTRO_CODENAME="$(. /etc/os-release && echo "${VERSION_CODENAME}")"
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${DISTRO_ID} ${DISTRO_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
else
  log "Docker already installed, skipping"
fi

# ---------------------------------------------------------------------------
# WireGuard via wg-easy (admin UI bound to loopback ONLY)
# ---------------------------------------------------------------------------

log "Deploying wg-easy container"
mkdir -p /opt/wg-easy
docker rm -f wg-easy >/dev/null 2>&1 || true
# --network host is required here: without it, wg0 is created only inside
# the container's own network namespace and never appears on the host, so
# host-side Samba (bound to "wg0") would never find that interface. Under
# host networking, wg-easy's UI listens on the host's 0.0.0.0:${WG_UI_PORT}
# directly - it is kept loopback-only by ufw's default-deny (no public rule
# is added for that port below), not by Docker port mapping.
docker run -d \
  --name=wg-easy \
  --restart unless-stopped \
  --network host \
  --cap-add=NET_ADMIN --cap-add=SYS_MODULE \
  --sysctl net.ipv4.ip_forward=1 \
  --sysctl net.ipv4.conf.all.src_valid_mark=1 \
  -v /opt/wg-easy:/etc/wireguard \
  -e WG_HOST="${PUBLIC_IP}" \
  -e WG_PORT="${WG_PORT}" \
  -e PORT="${WG_UI_PORT}" \
  -e WG_DEFAULT_ADDRESS="10.8.0.x" \
  -e PASSWORD="${WG_EASY_PASSWORD}" \
  weejewel/wg-easy

log "Waiting for wg0 interface to come up on the host"
for _ in $(seq 1 30); do
  if ip link show "${WG_IFACE}" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! ip link show "${WG_IFACE}" >/dev/null 2>&1; then
  echo "ERROR: ${WG_IFACE} did not appear on the host after 30s. Check: docker logs wg-easy" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Firewall: only SSH + WireGuard UDP reachable publicly
# ---------------------------------------------------------------------------

log "Configuring ufw firewall"
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow "${SSH_PORT}"/tcp comment 'SSH'
ufw allow "${WG_PORT}"/udp comment 'WireGuard'
# Samba is intentionally restricted to the VPN subnet only, never public.
# NetBIOS (137/138) is UDP, session/SMB (139/445) is TCP - ufw needs proto
# specified explicitly and won't accept a mixed-protocol port list.
ufw allow from "${WG_SUBNET}" to any port 137,138 proto udp comment 'Samba NetBIOS (VPN clients only)'
ufw allow from "${WG_SUBNET}" to any port 139,445 proto tcp comment 'Samba (VPN clients only)'
ufw --force enable

cat > /etc/sysctl.d/99-wireguard-forward.conf <<EOF
net.ipv4.ip_forward=1
EOF
sysctl --system >/dev/null

# ---------------------------------------------------------------------------
# Mount the Hetzner Storage Box over CIFS
# ---------------------------------------------------------------------------

log "Mounting Hetzner Storage Box via CIFS"
mkdir -p "${STORAGEBOX_MOUNT}"

cat > "${CREDENTIALS_FILE}" <<EOF
username=${STORAGEBOX_USER}
password=${STORAGEBOX_PASS}
EOF
chmod 600 "${CREDENTIALS_FILE}"

cat > /etc/systemd/system/mnt-storagebox.mount <<EOF
[Unit]
Description=Hetzner Storage Box (CIFS)
After=network-online.target
Wants=network-online.target

[Mount]
What=//${STORAGEBOX_HOST}/backup
Where=${STORAGEBOX_MOUNT}
Type=cifs
Options=credentials=${CREDENTIALS_FILE},vers=3.0,uid=root,gid=root,iocharset=utf8,file_mode=0770,dir_mode=0770
TimeoutSec=30

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now mnt-storagebox.mount

if ! mountpoint -q "${STORAGEBOX_MOUNT}"; then
  echo "ERROR: Storage Box failed to mount at ${STORAGEBOX_MOUNT}. Check credentials and that this VPS's IP is allow-listed on the Storage Box." >&2
  exit 1
fi
echo "  Mounted //${STORAGEBOX_HOST}/backup -> ${STORAGEBOX_MOUNT}"

# ---------------------------------------------------------------------------
# Samba re-share, bound to wg0 ONLY
# ---------------------------------------------------------------------------

log "Configuring Samba (bound to ${WG_IFACE} only)"

if ! id "${SAMBA_SYSTEM_USER}" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "${SAMBA_SYSTEM_USER}"
fi
printf '%s\n%s\n' "${SMB_SHARE_PASS}" "${SMB_SHARE_PASS}" | smbpasswd -a -s "${SAMBA_SYSTEM_USER}"
smbpasswd -e "${SAMBA_SYSTEM_USER}"

cp -n /etc/samba/smb.conf /etc/samba/smb.conf.orig 2>/dev/null || true

cat > /etc/samba/smb.conf <<EOF
[global]
   workgroup = WORKGROUP
   server string = Storage Box Relay
   security = user
   map to guest = never
   # Core lockdown: only ever listen on the WireGuard interface, never
   # the public NIC, regardless of what firewall rules also say.
   interfaces = lo ${WG_IFACE}
   bind interfaces only = yes
   log file = /var/log/samba/log.%m
   max log size = 1000

[${SAMBA_SHARE_NAME}]
   path = ${STORAGEBOX_MOUNT}
   valid users = ${SAMBA_SYSTEM_USER}
   read only = no
   browsable = yes
   force user = root
EOF

# Samba is configured to bind only to wg0, which only exists once the
# wg-easy container (Docker) has started - without this override, a reboot
# could start smbd/nmbd before wg0 exists and reproduce the same bind
# failure. Make Samba wait on Docker and give the interface a moment.
mkdir -p /etc/systemd/system/smbd.service.d /etc/systemd/system/nmbd.service.d
for svc in smbd nmbd; do
  cat > "/etc/systemd/system/${svc}.service.d/override.conf" <<EOF
[Unit]
After=docker.service
Requires=docker.service

[Service]
ExecStartPre=/bin/sh -c 'for i in \$(seq 1 30); do ip link show ${WG_IFACE} >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1'
EOF
done
systemctl daemon-reload

systemctl enable --now smbd nmbd
systemctl restart smbd nmbd

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

log "Setup complete"
cat <<SUMMARY

MANUAL STEP STILL REQUIRED:
  Lock down the Storage Box's own firewall so only this VPS may reach it:
    Hetzner Robot panel -> your Storage Box -> "Access" tab ->
    restrict Samba/CIFS access to source IP: ${PUBLIC_IP}

Manage WireGuard peers (wg-easy admin UI, loopback-only by design):
  1. From your management server (already SSH'd into this VPS), run:
       ssh -L ${WG_UI_PORT}:127.0.0.1:${WG_UI_PORT} root@${PUBLIC_IP} -p ${SSH_PORT}
  2. Browse to http://localhost:${WG_UI_PORT} and log in with the admin
     password you entered above.
  3. Add a client, download its config / scan its QR code.

Once connected via WireGuard, map the network drive:
  Windows : \\\\${WG_HOST_ADDR}\\${SAMBA_SHARE_NAME}
  macOS   : smb://${WG_HOST_ADDR}/${SAMBA_SHARE_NAME}
  Linux   : mount -t cifs //${WG_HOST_ADDR}/${SAMBA_SHARE_NAME} <mountpoint> -o username=${SAMBA_SYSTEM_USER}

  Samba login user : ${SAMBA_SYSTEM_USER}
  Samba login pass : ${SMB_SHARE_PASS}
  (also written nowhere else - copy it now)

Exposed publicly  : SSH (${SSH_PORT}/tcp), WireGuard (${WG_PORT}/udp) only.
Not exposed       : wg-easy UI (loopback only), Samba (wg0 only).
SUMMARY
