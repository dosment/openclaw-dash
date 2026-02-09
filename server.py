#!/usr/bin/env python3
"""OpenClaw Dashboard - Local web server for OpenClaw visibility with SSE."""

import json
import re
import time
import threading
import queue
from datetime import datetime, timedelta, timezone
from pathlib import Path
from flask import Flask, jsonify, render_template, Response
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

app = Flask(__name__)

OPENCLAW_DIR = Path.home() / ".openclaw"
CRON_FILE = OPENCLAW_DIR / "cron" / "jobs.json"
CONFIG_FILE = OPENCLAW_DIR / "openclaw.json"

# Model cache (refreshed on startup and periodically)
_model_cache = {"models": [], "aliases": {}, "updated": 0}

def refresh_model_cache():
    """Fetch available models from OpenClaw CLI."""
    global _model_cache
    try:
        import subprocess
        import shutil
        
        # Find openclaw binary
        openclaw_bin = shutil.which("openclaw")
        if not openclaw_bin:
            # Check common locations
            for path in [
                Path.home() / ".nvm/versions/node/v22.22.0/bin/openclaw",
                Path("/usr/local/bin/openclaw"),
                Path("/usr/bin/openclaw"),
            ]:
                if path.exists():
                    openclaw_bin = str(path)
                    break
        if not openclaw_bin:
            return
        
        # Ensure node is in PATH for nvm-installed openclaw
        import os
        env = os.environ.copy()
        nvm_bin = str(Path.home() / ".nvm/versions/node/v22.22.0/bin")
        env["PATH"] = f"{nvm_bin}:{env.get('PATH', '')}"
        env["CI"] = "true"  # Suppress interactive prompts
        env["TERM"] = "dumb"
        
        result = subprocess.run(
            [openclaw_bin, "models", "list"],
            capture_output=True, text=True, timeout=30, env=env
        )
        if result.returncode != 0:
            return
        
        models = []
        aliases = {}
        for line in result.stdout.strip().split("\n")[1:]:  # Skip header
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 1:
                model_id = parts[0]  # e.g., "anthropic/claude-opus-4-5-20251101"
                # Extract short name from model ID
                short = model_id.split("/")[-1]  # "claude-opus-4-5-20251101"
                # Simplify common patterns
                if "opus-4-6" in short or "opus-2026" in short:
                    display = "opus-4.6"
                elif "opus" in short:
                    display = "opus-4.5"
                elif "sonnet" in short:
                    display = "sonnet"
                elif "haiku" in short:
                    display = "haiku"
                elif "gemini-3" in short or "flash-3" in short:
                    display = "flash-3"
                elif "gemini-2" in short or "flash" in short:
                    display = "flash-2.5"
                elif "kimi" in short or "k2.5" in short:
                    display = "kimi-k2.5"
                elif "deepseek" in short:
                    display = "deepseek"
                elif "gpt-4o" in short:
                    display = "gpt-4o"
                elif "gpt-4" in short:
                    display = "gpt-4"
                else:
                    display = short[:15]
                
                if display not in models:
                    models.append(display)
                aliases[model_id] = display
                aliases[short] = display
                
                # Parse aliases from tags (e.g., "alias:sonnet")
                if "alias:" in line:
                    for match in re.findall(r'alias:(\w+)', line):
                        aliases[match] = display
        
        _model_cache = {"models": models, "aliases": aliases, "updated": time.time()}
    except Exception as e:
        pass  # Silently fall back to pattern matching

# Refresh on startup
refresh_model_cache()

# Agent base directories (add additional paths here if needed)
AGENT_BASES = [
    OPENCLAW_DIR / "agents",
]

# Customize these for your setup
EXCLUDED_AGENTS = set()  # Agents to hide, e.g., {"shadow", "test"}
AGENT_ALIASES = {}  # Rename agents in UI, e.g., {"main": "assistant"}

def get_all_agent_dirs():
    """Get all agent session directories from all bases."""
    agents = {}
    for base in AGENT_BASES:
        if not base.exists():
            continue
        for agent_dir in base.iterdir():
            if agent_dir.is_dir() and agent_dir.name not in EXCLUDED_AGENTS:
                sessions_dir = agent_dir / "sessions"
                if sessions_dir.exists():
                    agent_name = agent_dir.name
                    # Count session files to prefer directories with actual data
                    session_count = len(list(sessions_dir.glob("*.jsonl")))
                    if agent_name not in agents or session_count > 0:
                        # Prefer directories with session files
                        existing_count = len(list(agents.get(agent_name, sessions_dir).glob("*.jsonl"))) if agent_name in agents else 0
                        if session_count >= existing_count:
                            agents[agent_name] = sessions_dir
    return agents

# SSE clients
clients = []
clients_lock = threading.Lock()

def get_default_model():
    """Get the default model from OpenClaw config."""
    try:
        with open(CONFIG_FILE) as f:
            config = json.load(f)
        agents = config.get("agents", {})
        agent_list = agents.get("list", [])
        # Check first agent in list for model override
        if agent_list and len(agent_list) > 0:
            model = agent_list[0].get("model")
            if model:
                return categorize_model(model)
        defaults = agents.get("defaults", {})
        model_config = defaults.get("model", {})
        if isinstance(model_config, dict):
            return categorize_model(model_config.get("primary", ""))
        return categorize_model(model_config)
    except:
        return "opus-4.5"

def categorize_model(model_str):
    """Categorize model string into display name using cached model list."""
    if not model_str:
        return None
    
    # Check cache first
    if model_str in _model_cache["aliases"]:
        return _model_cache["aliases"][model_str]
    
    # Fallback to pattern matching for models not in cache
    m = model_str.lower()
    if 'opus-4.6' in m or 'opus-2026' in m: return 'opus-4.6'
    if 'opus-4.5' in m or 'opus-2025' in m or 'opus' in m: return 'opus-4.5'
    if 'sonnet' in m: return 'sonnet'
    if 'haiku' in m: return 'haiku'
    if 'kimi' in m or 'k2.5' in m or 'k2-5' in m: return 'kimi-k2.5'
    if 'gemini-3' in m or 'flash3' in m or 'flash-3' in m: return 'flash-3'
    if 'gemini-2.5' in m or 'gemini-2' in m or ('flash' in m and '3' not in m): return 'flash-2.5'
    if 'gpt-4o' in m: return 'gpt-4o'
    if 'gpt-4' in m or 'gpt4' in m: return 'gpt-4'
    if 'deepseek' in m: return 'deepseek'
    if 'neotron' in m or 'local' in m: return 'neotron'
    if 'delivery' in m or 'mirror' in m: return 'delivery'
    if 'embedding' in m or 'embed' in m: return 'embed'
    return 'other'

def parse_simple_cron(expr):
    """Parse simple cron expression and find next occurrence."""
    try:
        parts = expr.strip().split()
        if len(parts) != 5:
            return None
        minute, hour, dom, month, dow = parts
        now = datetime.now()
        if dom == "*" and month == "*":
            if "," in hour:
                hours = [int(h) for h in hour.split(",")]
            elif hour == "*":
                hours = list(range(24))
            else:
                hours = [int(hour)]
            if "," in minute:
                mins = [int(m) for m in minute.split(",")]
            elif minute == "*":
                mins = [0]
            else:
                mins = [int(minute)]
            for day_offset in range(2):
                check_date = now + timedelta(days=day_offset)
                for h in sorted(hours):
                    for m in sorted(mins):
                        candidate = check_date.replace(hour=h, minute=m, second=0, microsecond=0)
                        if candidate > now:
                            return candidate
        return None
    except:
        return None

def format_relative_time(dt):
    """Format datetime as relative time string."""
    if not dt:
        return ""
    now = datetime.now()
    delta = dt - now
    if delta.total_seconds() < 0:
        return "past"
    if delta.days > 0:
        return f"in {delta.days}d"
    hours = delta.seconds // 3600
    mins = (delta.seconds % 3600) // 60
    if hours > 0:
        return f"in {hours}h{mins}m"
    return f"in {mins}m"

def get_next_fire(schedule):
    """Calculate next fire time from schedule."""
    try:
        if schedule.get("kind") == "cron":
            expr = schedule.get("expr", "")
            if expr:
                parts = expr.split()
                if len(parts) == 5:
                    minute, hour, dom, month, dow = parts
                    # Check if it's a daily job (runs every day at a specific time)
                    is_daily = dom == "*" and month == "*" and dow == "*" and hour != "*" and minute != "*"
                    if is_daily:
                        return f"daily@{hour}:{minute.zfill(2) if minute.isdigit() else minute}"
                    # For non-daily, show relative time if we can parse it
                    next_dt = parse_simple_cron(expr)
                    if next_dt:
                        return format_relative_time(next_dt)
                    # Fallback to @time format
                    if hour != "*" and minute != "*":
                        return f"@{hour}:{minute.zfill(2) if minute.isdigit() else minute}"
                return expr[:12]
        elif schedule.get("kind") == "at":
            at_str = schedule.get("at", "")
            if at_str:
                at_dt = datetime.fromisoformat(at_str.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                if at_dt < now:
                    return "past"
                delta = at_dt - now
                if delta.days > 0:
                    # Convert to local time for display
                    local_dt = at_dt.astimezone()
                    return local_dt.strftime("%b %d")
                hours = delta.seconds // 3600
                mins = (delta.seconds % 3600) // 60
                if hours > 0:
                    return f"in {hours}h{mins}m"
                return f"in {mins}m"
        elif schedule.get("kind") == "every":
            every_ms = schedule.get("everyMs", 0)
            if every_ms:
                hours = every_ms // 3600000
                mins = (every_ms % 3600000) // 60000
                if hours > 0:
                    return f"every {hours}h"
                return f"every {mins}m"
    except:
        pass
    return ""

def get_cron_jobs():
    if not CRON_FILE.exists(): return []
    try:
        default_model = get_default_model()
        with open(CRON_FILE) as f:
            data = json.load(f)
        jobs = []
        for job in data.get("jobs", []):
            model = None
            if job.get("payload", {}).get("model"):
                model = categorize_model(job["payload"]["model"])
            if not model:
                model = default_model
            state = job.get("state", {})
            status = "ok"
            last_error = ""
            if state.get("lastStatus") == "error":
                status = "err"
                last_error = state.get("lastError", "")[:100]
            elif not job.get("enabled", True):
                status = "off"
            schedule = job.get("schedule", {})
            next_fire = get_next_fire(schedule) if job.get("enabled", True) else "disabled"
            jobs.append({
                "id": job.get("id", ""),
                "name": job.get("name", "?"),
                "enabled": job.get("enabled", True),
                "model": model,
                "status": status,
                "lastError": last_error,
                "nextFire": next_fire,
                "lastRun": state.get("lastRun", ""),
            })
        jobs.sort(key=lambda x: (not x["enabled"], x["nextFire"] if x["nextFire"] != "past" else "zzz"))
        return jobs
    except Exception as e:
        print(f"Cron error: {e}")
        return []

def get_git_status():
    """Get last commit time from dashboard repo."""
    try:
        import subprocess
        # Get last commit timestamp
        result = subprocess.run(
            ["git", "log", "-1", "--format=%ct"],
            capture_output=True, text=True, timeout=5,
            cwd=Path(__file__).parent
        )
        if result.returncode == 0 and result.stdout.strip():
            commit_ts = int(result.stdout.strip())
            now = datetime.now().timestamp()
            age_secs = now - commit_ts
            age_mins = int(age_secs / 60)
            if age_mins < 60:
                ago = f"{age_mins}m ago"
            elif age_mins < 1440:
                ago = f"{age_mins // 60}h ago"
            else:
                ago = f"{age_mins // 1440}d ago"
            return {"lastCommit": ago, "timestamp": commit_ts}
    except:
        pass
    return None

def get_email_status():
    """Get last email check time from cron job."""
    if not CRON_FILE.exists():
        return None
    try:
        with open(CRON_FILE) as f:
            data = json.load(f)
        for job in data.get("jobs", []):
            if "email" in job.get("name", "").lower():
                state = job.get("state", {})
                last_run_ms = state.get("lastRunAtMs")
                if last_run_ms:
                    now_ms = datetime.now().timestamp() * 1000
                    age_ms = now_ms - last_run_ms
                    age_mins = int(age_ms / 60000)
                    if age_mins < 60:
                        ago = f"{age_mins}m ago"
                    elif age_mins < 1440:
                        ago = f"{age_mins // 60}h ago"
                    else:
                        ago = f"{age_mins // 1440}d ago"
                    return {
                        "lastCheck": ago,
                        "lastRunMs": last_run_ms,
                        "status": state.get("lastStatus", "unknown"),
                        "enabled": job.get("enabled", True),
                    }
        return None
    except:
        return None

def count_session_messages(session_file):
    """Count actual messages in a session .jsonl file."""
    try:
        if not session_file.exists():
            return 0
        count = 0
        with open(session_file) as f:
            for line in f:
                try:
                    msg = json.loads(line)
                    if msg.get("type") == "message":
                        count += 1
                except:
                    continue
        return count
    except:
        return 0

def extract_channel(key):
    """Extract channel type from session key."""
    # Keys like: agent:<name>:discord:channel:123, agent:<name>:telegram:chat:123, agent:<name>:main
    parts = key.split(":")
    if len(parts) >= 3:
        channel = parts[2].lower()
        # Normalize channel names
        channel_map = {
            "discord": "discord",
            "telegram": "telegram",
            "whatsapp": "whatsapp",
            "signal": "signal",
            "slack": "slack",
            "imessage": "imessage",
            "bluebubbles": "imessage",
            "googlechat": "gchat",
            "msteams": "teams",
            "matrix": "matrix",
            "mattermost": "mattermost",
            "line": "line",
            "feishu": "feishu",
            "nostr": "nostr",
            "twitch": "twitch",
            "zalo": "zalo",
            "webchat": "web",
            "nextcloud-talk": "nextcloud",
            "nextcloud": "nextcloud",
            "main": "cli",
            "cron": "cron",
            "isolated": "cron",
            "hook": "hook",
            "openresponses": "api",
            "openresponses-user": "api",
            "voice": "voice",
        }
        return channel_map.get(channel, channel)
    return "other"

def get_sessions():
    agent_dirs = get_all_agent_dirs()
    now_ms = datetime.now().timestamp() * 1000
    main_sessions = []
    sub_agents = []
    
    for agent_name, sessions_dir in agent_dirs.items():
        sessions_file = sessions_dir / "sessions.json"
        if not sessions_file.exists():
            continue
        try:
            with open(sessions_file) as f:
                data = json.load(f)
            for key, info in data.items():
                if not isinstance(info, dict): continue
                updated = info.get("updatedAt", 0)
                age_ms = now_ms - updated
                if age_ms < 60000: status = "active"
                elif age_ms < 600000: status = "recent"
                else: status = "idle"
                display = info.get("displayName") or key
                display = display.replace("discord:", "")
                display = re.sub(r'G-\d+', '', display)
                display = re.sub(r'\b\d{17,20}\b', '', display)
                display = re.sub(r'^[-_:]+|[-_:]+$', '', display).strip()
                display = re.sub(r'[-_:]{2,}', '-', display)
                if not display or display in ("-", "G", ""):
                    display = key.split(":")[-1][:20] if ":" in key else key[:20]
                if len(display) <= 2 and not display.startswith("#"):
                    continue
                if len(display) > 35: display = display[:32] + "..."
                session_id = info.get("sessionId", "")
                msg_count = 0
                if session_id:
                    session_jsonl = sessions_dir / f"{session_id}.jsonl"
                    msg_count = count_session_messages(session_jsonl)
                tokens = info.get("totalTokens", 0)
                channel = extract_channel(key)
                sess = {
                    "key": key,
                    "agent": AGENT_ALIASES.get(agent_name, agent_name),
                    "channel": channel,
                    "displayName": display,
                    "model": categorize_model(info.get("model", "")) or "default",
                    "tokens": tokens,
                    "messages": msg_count,
                    "updatedAt": updated,
                    "status": status,
                }
                if ":cron:" in key or ":isolated:" in key or "isolated" in str(info.get("kind", "")):
                    sub_agents.append(sess)
                else:
                    main_sessions.append(sess)
        except Exception as e:
            print(f"Error processing {agent_name}: {e}")
            continue
    
    # Sort by tokens, but show all sessions (UI will handle scrolling)
    main_sessions.sort(key=lambda x: x["tokens"], reverse=True)
    sub_agents.sort(key=lambda x: (x["status"] != "active", -x["updatedAt"]))
    # Return all sessions - let UI filter/scroll
    return main_sessions, sub_agents

def get_usage():
    # Use local time for day boundaries
    now_local = datetime.now().astimezone()
    today_start = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=7)
    # Convert to UTC for comparison with timestamps
    today_start_utc = today_start.astimezone(timezone.utc)
    week_start_utc = week_start.astimezone(timezone.utc)
    usage = {
        "today": {"by_model": {}, "other_samples": []},
        "week": {"by_model": {}, "other_samples": []},
    }
    agent_dirs = get_all_agent_dirs()
    cutoff = week_start_utc.timestamp()
    
    for agent_name, sessions_dir in agent_dirs.items():
        try:
            recent_files = [f for f in sessions_dir.glob("*.jsonl") if f.stat().st_mtime > cutoff]
        except:
            continue
        for jf in recent_files:
            try:
                with open(jf) as f:
                    for line in f:
                        try:
                            msg = json.loads(line)
                            if msg.get("type") != "message": continue
                            ts = msg.get("timestamp", "")
                            if not ts: continue
                            msg_time = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                            if msg_time < week_start_utc: continue
                            message = msg.get("message", {})
                            raw_model = message.get("model", "")
                            model = categorize_model(raw_model)
                            if model is None: continue
                            if model == "other" and len(usage["week"]["other_samples"]) < 5:
                                usage["week"]["other_samples"].append(raw_model)
                            usage["week"]["by_model"][model] = usage["week"]["by_model"].get(model, 0) + 1
                            if msg_time >= today_start_utc:
                                usage["today"]["by_model"][model] = usage["today"]["by_model"].get(model, 0) + 1
                        except: continue
            except: continue
    return usage

def get_activity(limit=20):
    activity = []
    agent_dirs = get_all_agent_dirs()
    
    for agent_name, sessions_dir in agent_dirs.items():
        try:
            files = sorted(sessions_dir.glob("*.jsonl"), key=lambda x: x.stat().st_mtime, reverse=True)
        except:
            continue
        for jf in files[:5]:
            with open(jf) as f:
                lines = f.readlines()
            for line in lines[-40:]:
                try:
                    msg = json.loads(line)
                    if msg.get("type") != "message": continue
                    message = msg.get("message", {})
                    role = message.get("role", "")
                    ts = msg.get("timestamp", "")
                    model = categorize_model(message.get("model", "")) or ""
                    if role == "user":
                        content = message.get("content", [])
                        text = next((c.get("text", "")[:80] for c in content if isinstance(c, dict) and c.get("type") == "text"), "")
                        if text and not text.startswith("System:") and not text.startswith("GatewayRestart"):
                            activity.append({"type": "user", "ts": ts, "text": text, "model": ""})
                    elif role == "assistant":
                        content = message.get("content", [])
                        tool_calls = [c for c in content if isinstance(c, dict) and c.get("type") == "toolCall"]
                        if tool_calls:
                            # Build descriptive tool text
                            tool_descs = []
                            for tc in tool_calls[:3]:
                                name = tc.get("name", "?")
                                args = tc.get("arguments", {})
                                if name in ("edit", "Edit"):
                                    path = args.get("file_path") or args.get("path") or ""
                                    fname = path.split("/")[-1] if path else "?"
                                    tool_descs.append(f"edit {fname}")
                                elif name in ("write", "Write"):
                                    path = args.get("file_path") or args.get("path") or ""
                                    fname = path.split("/")[-1] if path else "?"
                                    tool_descs.append(f"write {fname}")
                                elif name in ("Read", "read"):
                                    path = args.get("file_path") or args.get("path") or ""
                                    fname = path.split("/")[-1] if path else "?"
                                    tool_descs.append(f"read {fname}")
                                elif name == "exec":
                                    cmd = args.get("command", "")[:40]
                                    tool_descs.append(f"$ {cmd}")
                                elif name == "cron":
                                    action = args.get("action", "")
                                    tool_descs.append(f"cron:{action}")
                                elif name == "message":
                                    action = args.get("action", "send")
                                    tool_descs.append(f"msg:{action}")
                                elif name == "web_search":
                                    query = args.get("query", "")[:30]
                                    tool_descs.append(f"search: {query}")
                                elif name == "web_fetch":
                                    url = args.get("url", "")
                                    domain = url.split("/")[2] if "/" in url else url[:20]
                                    tool_descs.append(f"fetch {domain}")
                                else:
                                    tool_descs.append(name)
                            text = " | ".join(tool_descs)
                            activity.append({"type": "tool", "ts": ts, "text": text, "model": model, "detail": text})
                        else:
                            text = next((c.get("text", "")[:80] for c in content if isinstance(c, dict) and c.get("type") == "text"), "")
                            if text and text not in ("NO_REPLY", "HEARTBEAT_OK", ""):
                                activity.append({"type": "bot", "ts": ts, "text": text, "model": model})
                except: continue
    activity.sort(key=lambda x: x.get("ts", ""), reverse=True)
    return activity[:limit]

def check_internet():
    """Quick connectivity check with latency."""
    import socket
    import time
    try:
        socket.setdefaulttimeout(2)
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("8.8.8.8", 53))
        latency = int((time.time() - start) * 1000)
        sock.close()
        return {"status": "ok", "latency": latency}
    except:
        pass
    try:
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("1.1.1.1", 53))
        latency = int((time.time() - start) * 1000)
        sock.close()
        return {"status": "ok", "latency": latency}
    except:
        return {"status": "down", "latency": None}

# Cache for openclaw status (don't poll too frequently)
_openclaw_status_cache = {"data": None, "updated": 0}

def get_openclaw_status():
    """Get gateway health and security audit from openclaw status."""
    global _openclaw_status_cache
    now = time.time()
    
    # Cache for 30 seconds
    if _openclaw_status_cache["data"] and (now - _openclaw_status_cache["updated"]) < 30:
        return _openclaw_status_cache["data"]
    
    try:
        import subprocess
        import shutil
        
        openclaw_bin = shutil.which("openclaw")
        if not openclaw_bin:
            for path in [
                Path.home() / ".nvm/versions/node/v22.22.0/bin/openclaw",
                Path("/usr/local/bin/openclaw"),
            ]:
                if path.exists():
                    openclaw_bin = str(path)
                    break
        if not openclaw_bin:
            return None
        
        import os
        env = os.environ.copy()
        nvm_bin = str(Path.home() / ".nvm/versions/node/v22.22.0/bin")
        env["PATH"] = f"{nvm_bin}:{env.get('PATH', '')}"
        env["CI"] = "true"  # Suppress interactive prompts
        env["TERM"] = "dumb"
        
        result = subprocess.run(
            [openclaw_bin, "status", "--json"],
            capture_output=True, text=True, timeout=30, env=env
        )
        if result.returncode != 0:
            return None
        
        # Strip any header/warning lines before JSON
        stdout = result.stdout
        json_start = stdout.find('{')
        if json_start == -1:
            return None
        data = json.loads(stdout[json_start:])
        
        # Extract what we need
        gateway = data.get("gateway", {})
        security_audit = data.get("securityAudit", {})
        security = security_audit.get("summary", {})
        findings = security_audit.get("findings", [])
        
        status = {
            "gateway": {
                "reachable": gateway.get("reachable", False),
                "latency": gateway.get("connectLatencyMs"),
                "mode": gateway.get("mode", "unknown"),
            },
            "security": {
                "critical": security.get("critical", 0),
                "warn": security.get("warn", 0),
                "info": security.get("info", 0),
                "findings": [
                    {
                        "severity": f.get("severity", "info"),
                        "title": f.get("title", "Unknown"),
                        "detail": f.get("detail", ""),
                        "fix": f.get("remediation", ""),
                    }
                    for f in findings
                ],
            }
        }
        
        _openclaw_status_cache = {"data": status, "updated": now}
        return status
    except Exception as e:
        import traceback
        print(f"get_openclaw_status error: {e}")
        traceback.print_exc()
        return None

def get_recent_errors():
    """Get recent errors from cron jobs."""
    errors = []
    jobs = get_cron_jobs()
    for job in jobs:
        if job["status"] == "err" and job["lastError"]:
            errors.append({
                "source": f"cron:{job['name']}",
                "error": job["lastError"],
                "ts": job.get("lastRun", ""),
            })
    return errors[:10]

def build_status():
    """Build the full status payload."""
    jobs = get_cron_jobs()
    main_sessions, sub_agents = get_sessions()
    usage = get_usage()
    activity = get_activity()
    errors = get_recent_errors()
    enabled_jobs = [j for j in jobs if j["enabled"]]
    disabled_jobs = [j for j in jobs if not j["enabled"]]
    ok_jobs = [j for j in enabled_jobs if j["status"] == "ok"]
    err_jobs = [j for j in enabled_jobs if j["status"] == "err"]
    active_sessions = len([s for s in main_sessions if s["status"] == "active"])
    active_subs = len([s for s in sub_agents if s["status"] == "active"])
    
    # Channel breakdown (exclude cron/isolated from main channel counts)
    channel_counts = {}
    channel_active = {}
    for s in main_sessions:
        ch = s.get("channel", "other")
        channel_counts[ch] = channel_counts.get(ch, 0) + 1
        if s["status"] == "active":
            channel_active[ch] = True
    
    # Get unique agents after applying aliases
    raw_agents = get_all_agent_dirs().keys()
    agents = list(set(AGENT_ALIASES.get(a, a) for a in raw_agents))
    internet = check_internet()
    openclaw_status = get_openclaw_status()
    email_status = get_email_status()
    git_status = get_git_status()
    return {
        "ts": datetime.now().isoformat(),
        "agents": agents,
        "internet": internet,
        "email": email_status,
        "git": git_status,
        "openclaw": openclaw_status,
        "defaultModel": get_default_model(),
        "availableModels": _model_cache.get("models", []),
        "channels": {
            "counts": channel_counts,
            "active": list(channel_active.keys()),
        },
        "summary": {
            "jobs_ok": len(ok_jobs),
            "jobs_total": len(enabled_jobs),
            "jobs_disabled": len(disabled_jobs),
            "jobs_healthy": len(err_jobs) == 0,
            "active_sessions": active_sessions,
            "active_subs": active_subs,
            "total_subs": len(sub_agents),
            "error_count": len(err_jobs),
        },
        "jobs": jobs,
        "main_sessions": main_sessions,
        "sub_agents": sub_agents,
        "usage": usage,
        "activity": activity,
        "errors": errors,
    }

# SSE: File watcher to trigger updates
class OpenClawEventHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_push = 0
        self.debounce_ms = 500  # Don't push more than every 500ms
    
    def on_any_event(self, event):
        if event.is_directory:
            return
        # Only care about relevant files
        path = event.src_path
        if not (path.endswith('.jsonl') or path.endswith('.json')):
            return
        # Debounce
        now = time.time() * 1000
        if now - self.last_push < self.debounce_ms:
            return
        self.last_push = now
        # Push update to all clients
        push_update()

def push_update():
    """Push status update to all SSE clients."""
    try:
        data = build_status()
        message = f"data: {json.dumps(data)}\n\n"
        with clients_lock:
            dead = []
            for q in clients:
                try:
                    q.put_nowait(message)
                except:
                    dead.append(q)
            for q in dead:
                clients.remove(q)
    except Exception as e:
        print(f"Push error: {e}")

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/api/status")
def api_status():
    return jsonify(build_status())

@app.route("/api/stream")
def api_stream():
    """SSE endpoint for real-time updates."""
    def generate():
        q = queue.Queue()
        with clients_lock:
            clients.append(q)
        try:
            # Send initial state
            data = build_status()
            yield f"data: {json.dumps(data)}\n\n"
            # Wait for updates
            while True:
                try:
                    message = q.get(timeout=30)  # Heartbeat every 30s
                    yield message
                except queue.Empty:
                    yield ": heartbeat\n\n"  # Keep connection alive
        finally:
            with clients_lock:
                if q in clients:
                    clients.remove(q)
    
    return Response(generate(), mimetype='text/event-stream', headers={
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no',
    })

def start_watcher():
    """Start file system watcher in background thread."""
    event_handler = OpenClawEventHandler()
    observer = Observer()
    # Watch all agent session directories
    agent_dirs = get_all_agent_dirs()
    for agent_name, sessions_dir in agent_dirs.items():
        observer.schedule(event_handler, str(sessions_dir), recursive=False)
        print(f"Watching: {sessions_dir}")
    # Watch cron file
    observer.schedule(event_handler, str(CRON_FILE.parent), recursive=False)
    observer.start()
    print(f"File watcher started for {len(agent_dirs)} agents + cron")

if __name__ == "__main__":
    start_watcher()
    app.run(host="0.0.0.0", port=3333, debug=False, threaded=True)
