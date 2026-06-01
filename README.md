# Blitz AmneziaWG Panel

Clean web panel for AmneziaWG with two compatible profiles:

- **Amnezia 2.0**: full AWG profile with S3/S4 parameters.
- **Legacy / Amnezia 1.x**: separate profile without S3/S4 for older clients.
- Full tunnel and split tunnel client exports.
- Native AmneziaVPN import links and multi-part QR codes.
- Russian / English panel language switch in settings.
- Docker-based web panel installation.

## One-command install

Run as `root` on Ubuntu/Debian:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kuznecovpasa807-ui/Blits-Amnezia.WG/main/install.sh)
```

If the repository is private, keep it private and pass a GitHub token only for the install command:

```bash
export GITHUB_TOKEN='YOUR_GITHUB_TOKEN'
bash -c "$(curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" https://raw.githubusercontent.com/kuznecovpasa807-ui/Blits-Amnezia.WG/main/install.sh)"
unset GITHUB_TOKEN
```

The installer downloads the project, installs Docker if needed, installs/configures AmneziaWG, creates panel secrets, starts the panel, and asks only for the installation choices it cannot safely guess.

## Update

From the server directory:

```bash
cd /opt/blitz-amnezia-panel
git pull origin main
docker compose up -d --build
```

If the old install was cloned into another folder, run the same commands there.

## Ports

- Web panel: `80` in IP mode, or internal `1010` behind Nginx/domain mode.
- Amnezia 2.0: `51820/udp` by default.
- Legacy / Amnezia 1.x: `43913/udp` by default.

## QR import

AmneziaVPN may ask for more than one QR code. The panel now generates a QR series for every profile:

- Legacy: scan `QR 1/N`, then `QR 2/N`, and so on.
- Amnezia 2.0: scan its own `QR 1/N`, then the next parts.

Do not mix Legacy and 2.0 parts in one import.

## Security notes

- Runtime data is stored in `data/` and is ignored by Git.
- `.env`, keys, database files, generated configs, and backups are ignored by Git.
- API tokens and JWT secrets are generated during install and written to `data/panel.env`.
- Do not commit real GitHub tokens, root passwords, Telegram bot tokens, or generated client configs.

## Useful checks

```bash
docker compose ps
systemctl status awg-quick@awg0 --no-pager -l
systemctl status awg-quick@awg_legacy --no-pager -l
awg show
```
