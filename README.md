# OpenClaw Dashboard

A lightweight, real-time status dashboard for [OpenClaw](https://github.com/openclaw/openclaw) deployments.

![Dashboard Preview](https://img.shields.io/badge/status-beta-blue)

## Features

- **Real-time updates** via Server-Sent Events (SSE) — no polling
- **5 status tiles** — Enabled Jobs, Active Chats, Job Errors, Sub-Agents, Internet Latency
- **Session tracking** — message counts, token usage, model distribution
- **Cron job monitoring** — next fire times, error states, actual models
- **Multi-agent support** — filter by agent with dropdown
- **Colorblind-friendly** — uses shapes + colors (blue/orange/gray)

## Quick Start

```bash
# Clone the repo
git clone https://github.com/dosment/openclaw-dash.git
cd openclaw-dash

# Install dependencies
pip install -r requirements.txt

# Run
./start.sh
# or: python3 server.py
```

Dashboard runs at `http://localhost:3333`

## Requirements

- Python 3.9+
- OpenClaw installed and running
- Standard OpenClaw directory structure (`~/.openclaw/`)

## Configuration

Edit the top of `server.py` to customize:

```python
# Agents to exclude from the dashboard
EXCLUDED_AGENTS = {"shadow"}

# Rename agents in the UI (e.g., "main" -> "assistant")
AGENT_ALIASES = {"main": "assistant"}
```

## Running as a Service (systemd)

```bash
# Create user service
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/openclaw-dash.service << EOF
[Unit]
Description=OpenClaw Dashboard
After=network.target

[Service]
Type=simple
WorkingDirectory=/path/to/openclaw-dash
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

## License

MIT — do whatever you want with it.

## Contributing

PRs welcome. Keep it simple.
