# OpenClaw Dashboard

A lightweight, real-time status dashboard for [OpenClaw](https://github.com/openclaw/openclaw) deployments.

![Dashboard Preview](https://img.shields.io/badge/status-beta-blue)

## Features

- **Real-time updates** via Server-Sent Events (SSE) — no polling
- **8 status tiles** — Gateway, Internet, Email, Repo, Jobs, Chats, Sub-Agents, Channels
- **22 messaging channels** — Discord, Telegram, WhatsApp, Signal, Slack, iMessage, and more
- **Session tracking** — message counts, token usage, model distribution
- **Cron job monitoring** — next fire times, error states, daily@time format
- **Security audit** — shows warnings and fix hints from OpenClaw
- **Multi-agent support** — auto-discovers agents, filter by dropdown
- **Colorblind-friendly** — uses shapes + colors (blue/orange/gray)

## Quick Start

```bash
# Clone the repo
git clone https://github.com/dosment/openclaw-dash.git
cd openclaw-dash

# Install dependencies
pip install -r requirements.txt

# Run
python3 server.py
```

Dashboard runs at `http://localhost:3333`

## Requirements

- Python 3.9+
- Flask and watchdog (`pip install -r requirements.txt`)
- OpenClaw installed and running
- Standard OpenClaw directory structure (`~/.openclaw/`)

## Configuration

Edit the top of `server.py` to customize:

```python
# Agents to exclude from the dashboard (optional)
EXCLUDED_AGENTS = set()  # e.g., {"test", "dev"}

# Rename agents in the UI (optional)
AGENT_ALIASES = {}  # e.g., {"main": "assistant"}
```

## Running as a Service (systemd)

```bash
# Create user service
mkdir -p ~/.config/systemd/user

cat > ~/.config/systemd/user/openclaw-dash.service << 'EOF'
[Unit]
Description=OpenClaw Dashboard
After=network.target

[Service]
Type=simple
WorkingDirectory=%h/openclaw-dash
ExecStart=/usr/bin/python3 server.py
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF

# Enable and start
systemctl --user daemon-reload
systemctl --user enable openclaw-dash
systemctl --user start openclaw-dash
```

## For AI Agents

If you're an AI agent installing this for your user:

```bash
# 1. Clone to user's home directory
cd ~
git clone https://github.com/dosment/openclaw-dash.git

# 2. Install Python dependencies
cd openclaw-dash
pip install -r requirements.txt

# 3. Test it works
python3 server.py &
sleep 2
curl -s http://localhost:3333/api/status | head -c 100
kill %1

# 4. Set up as service (optional)
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/openclaw-dash.service << 'EOF'
[Unit]
Description=OpenClaw Dashboard
After=network.target

[Service]
Type=simple
WorkingDirectory=%h/openclaw-dash
ExecStart=/usr/bin/python3 server.py
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable openclaw-dash
systemctl --user start openclaw-dash

# 5. Verify
systemctl --user status openclaw-dash
```

The dashboard auto-discovers agents from `~/.openclaw/agents/` and models from `openclaw models list`.

## License

MIT — do whatever you want with it.

## Contributing

PRs welcome. Keep it simple.
