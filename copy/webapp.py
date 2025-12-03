#!/usr/bin/env python3
"""
Mini Suricata log dashboard.

Start with:
    uvicorn webapp:app --reload   # if using uvicorn
or:
    flask --app webapp run --debug
"""
from __future__ import annotations

import json
import math
import re
import subprocess
import sys
import threading
import time
from collections import Counter, deque
from datetime import datetime
from pathlib import Path
from typing import Deque, Dict, List

from flask import (
    Flask,
    Response,
    abort,
    render_template,
    request,
    send_file,
)

BASE_DIR = Path(__file__).resolve().parent
LOG_BASE_DIR = BASE_DIR / "copy"  # Basis map met alle suricata subdirectories
FETCH_SCRIPT = BASE_DIR / "fetch_logs.py"
ALERTS_PER_PAGE = 25

app = Flask(__name__)
# Zet caching uit voor development
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
_fetch_thread_started = False
_fetch_thread_lock = threading.Lock()

ALERT_REGEX = re.compile(
    r"^(?P<timestamp>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<message>.+?)\s+\[\*\*\]\s+\[Classification:\s+(?P<classification>.+?)\]\s+"
    r"\[Priority:\s+(?P<priority>\d+)\]\s+\{(?P<protocol>.+?)\}\s+"
    r"(?P<src>.+?)\s+->\s+(?P<dst>.+?)$"
)

SERVICE_KEYWORDS = [
    ("http", "HTTP"),
    ("https", "HTTPS"),
    ("tls", "TLS/SSL"),
    ("ssl", "TLS/SSL"),
    ("ssh", "SSH"),
    ("ftp", "FTP"),
    ("smtp", "SMTP"),
    ("pop3", "POP3"),
    ("imap", "IMAP"),
    ("dns", "DNS"),
    ("dhcp", "DHCP"),
    ("smb", "SMB"),
    ("rdp", "RDP"),
    ("mysql", "MySQL"),
    ("mssql", "MSSQL"),
    ("pgsql", "PostgreSQL"),
    ("mongo", "MongoDB"),
    ("redis", "Redis"),
    ("snmp", "SNMP"),
    ("ntp", "NTP"),
    ("icmp", "ICMP"),
    ("ldap", "LDAP"),
    ("kerberos", "Kerberos"),
]


def risk_label(priority: int) -> str:
    if priority <= 1:
        return "Critical"
    if priority == 2:
        return "High"
    if priority == 3:
        return "Medium"
    return "Low"


def parse_alert_line(line: str) -> Dict[str, object] | None:
    match = ALERT_REGEX.match(line.strip())
    if not match:
        return None
    data = match.groupdict()
    priority = int(data["priority"])
    ts = datetime.strptime(data["timestamp"], "%m/%d/%Y-%H:%M:%S.%f")
    src_ip, src_port = split_endpoint(data["src"])
    dst_ip, dst_port = split_endpoint(data["dst"])
    service = infer_service(data["message"], data["classification"], data["protocol"])
    return {
        "timestamp": ts,
        "message": data["message"],
        "classification": data["classification"],
        "priority": priority,
        "risk": risk_label(priority),
        "protocol": data["protocol"],
        "src": data["src"],
        "dst": data["dst"],
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "service": service,
        "sid": f"{data['gid']}:{data['sid']}:{data['rev']}",
    }


def split_endpoint(endpoint: str) -> tuple[str, str]:
    endpoint = endpoint.strip()
    if not endpoint:
        return "onbekend", "n/a"
    ip = endpoint
    port = "n/a"
    # Deel vanaf laatste dubbele punt als dat een poort lijkt (numeriek)
    if ":" in endpoint:
        candidate_ip, candidate_port = endpoint.rsplit(":", 1)
        if candidate_port.isdigit():
            ip = candidate_ip
            port = candidate_port
    return ip, port


def infer_service(message: str, classification: str, protocol: str) -> str:
    corpus = f"{message} {classification}".lower()
    for keyword, label in SERVICE_KEYWORDS:
        if keyword in corpus:
            return label
    # fallback op het protocol zelf (bijv. TCP/UDP)
    return protocol.upper()


def get_suricata_dirs() -> List[Path]:
    """Haalt ALLE directories op uit copy/ (niet alleen die beginnen met suricata_)."""
    if not LOG_BASE_DIR.exists():
        return []
    dirs = []
    try:
        for item in LOG_BASE_DIR.iterdir():
            if item.is_dir():
                dirs.append(item)
    except Exception as e:
        # Log error maar crash niet
        pass
    return sorted(dirs)


def iter_alerts(limit: int | None = None) -> List[Dict[str, object]]:
    """Haalt alerts op uit alle suricata directories."""
    results: List[Dict[str, object]] = []
    suricata_dirs = get_suricata_dirs()
    
    for log_dir in suricata_dirs:
        alerts_file = log_dir / "alerts.log"
        if not alerts_file.exists():
            continue
        
        with alerts_file.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                alert = parse_alert_line(line)
                if alert:
                    # Voeg directory naam toe aan alert voor tracking
                    alert["source_dir"] = log_dir.name
                    results.append(alert)
                    if limit and len(results) >= limit:
                        return results
    return results


def get_log_files() -> Dict[str, Dict[str, Path]]:
    """Haalt alle logbestanden op uit alle suricata directories.
    Retourneert dict met structuur: {dirname: {filename: path}}"""
    if not LOG_BASE_DIR.exists():
        return {}
    all_files = {}
    suricata_dirs = get_suricata_dirs()
    
    for log_dir in suricata_dirs:
        dir_files = {}
        try:
            for item in log_dir.iterdir():
                if item.is_file():
                    # Gebruik dirname/filename als key om uniek te zijn
                    key = f"{log_dir.name}/{item.name}"
                    dir_files[key] = item
        except Exception as e:
            # Log error maar ga door met volgende directory
            continue
        
        if dir_files:
            all_files[log_dir.name] = dir_files
    return all_files


def tail_file(path: Path, max_lines: int = 200) -> List[str]:
    buf: Deque[str] = deque(maxlen=max_lines)
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            buf.append(line.rstrip("\n"))
    return list(buf)


def build_alert_stats(alerts: List[Dict[str, object]]) -> Dict[str, object]:
    priority_counts = Counter(alert["priority"] for alert in alerts)
    classification_counts = Counter(alert["classification"] for alert in alerts)
    message_counts = Counter(alert["message"] for alert in alerts)
    src_counts = Counter(alert.get("src_ip", alert["src"]) for alert in alerts)
    dst_counts = Counter(alert.get("dst_ip", alert["dst"]) for alert in alerts)
    protocol_counts = Counter(alert["protocol"] for alert in alerts)
    dir_counts = Counter(alert.get("source_dir", "onbekend") for alert in alerts)
    service_counts = Counter(alert.get("service", alert["protocol"]) for alert in alerts)

    return {
        "total": len(alerts),
        "critical": sum(v for k, v in priority_counts.items() if k <= 1),
        "high": priority_counts[2],
        "medium": priority_counts[3],
        "low": sum(v for k, v in priority_counts.items() if k >= 4),
        "top_classifications": classification_counts.most_common(5),
        "top_signatures": message_counts.most_common(5),
        "top_sources": src_counts.most_common(5),
        "top_destinations": dst_counts.most_common(5),
        "top_protocols": protocol_counts.most_common(5),
        "top_directories": dir_counts.most_common(5),
        "top_services": service_counts.most_common(5),
    }


def start_fetch_logs_once() -> None:
    """Start fetch_logs.py één keer in een achtergrond-thread."""
    global _fetch_thread_started
    with _fetch_thread_lock:
        if _fetch_thread_started:
            return
        _fetch_thread_started = True

        if not FETCH_SCRIPT.exists():
            app.logger.warning("fetch_logs.py niet gevonden; automatische synchronisatie wordt overgeslagen.")
            return

        def runner() -> None:
            while True:
                try:
                    app.logger.info("Start fetch_logs.py proces.")
                    proc = subprocess.Popen(
                        [sys.executable, str(FETCH_SCRIPT)],
                        cwd=str(BASE_DIR),
                    )
                    exit_code = proc.wait()
                    if exit_code == 0:
                        app.logger.info("fetch_logs.py is gestopt (exit 0). Herstart over 10 seconden.")
                    else:
                        app.logger.warning("fetch_logs.py stopte met exitcode %s. Herstart over 10 seconden.", exit_code)
                except Exception as exc:
                    app.logger.error("Fout bij starten van fetch_logs.py: %s", exc)
                time.sleep(10)

        thread = threading.Thread(target=runner, name="fetch-logs-runner", daemon=True)
        thread.start()


@app.before_request
def bootstrap_background_jobs() -> None:
    """Bootstrap achtergrondtaken zodra de webapp een request krijgt (Flask 3 compat)."""
    start_fetch_logs_once()


def build_page_numbers(current: int, total: int, window: int = 1) -> List[int | None]:
    if total <= 1:
        return [1]
    candidates = {1, total, current}
    for offset in range(1, window + 1):
        candidates.add(current - offset)
        candidates.add(current + offset)
    valid = sorted(page for page in candidates if 1 <= page <= total)
    page_numbers: List[int | None] = []
    prev = None
    for page in valid:
        if prev is not None and page - prev > 1:
            page_numbers.append(None)
        page_numbers.append(page)
        prev = page
    return page_numbers


def paginate_items(items: List[Dict[str, object]], page: int, per_page: int = ALERTS_PER_PAGE) -> Dict[str, object]:
    total_items = len(items)
    per_page = per_page if per_page > 0 else ALERTS_PER_PAGE
    total_pages = max(1, math.ceil(total_items / per_page)) if total_items else 1
    if total_items == 0:
        page = 1
    else:
        page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    end = min(start + per_page, total_items)
    page_items = items[start:end]
    range_start_display = start + 1 if total_items else 0
    range_end_display = end
    return {
        "items": page_items,
        "page": page,
        "per_page": per_page,
        "total_items": total_items,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages and total_items > 0,
        "prev_page": page - 1 if page > 1 else 1,
        "next_page": page + 1 if page < total_pages else total_pages,
        "range_start": start,
        "range_end": end,
        "range_start_display": range_start_display,
        "range_end_display": range_end_display,
        "page_numbers": build_page_numbers(page, total_pages),
    }


def gather_dashboard_data() -> Dict[str, object]:
    alerts = iter_alerts()
    stats = build_alert_stats(alerts)
    files = []
    all_log_files = get_log_files()
    
    # Flatten alle bestanden met directory info
    for dirname, dir_files in all_log_files.items():
        for filekey, path in dir_files.items():
            files.append(
                {
                    "name": filekey,  # dirname/filename
                    "dirname": dirname,
                    "filename": path.name,
                    "size": path.stat().st_size,
                    "updated": datetime.fromtimestamp(path.stat().st_mtime),
                }
            )
    files.sort(key=lambda item: (item["dirname"], item["filename"]))

    suricata_dirs = get_suricata_dirs()

    return {
        "alerts": alerts,
        "stats": stats,
        "files": files,
        "suricata_dirs": [d.name for d in suricata_dirs],
    }


@app.route("/")
def dashboard() -> str:
    data = gather_dashboard_data()
    page = request.args.get("page", default=1, type=int) or 1
    pagination = paginate_items(data["alerts"], page, ALERTS_PER_PAGE)

    return render_template(
        "index.html",
        alerts=pagination["items"],
        stats=data["stats"],
        files=data["files"],
        log_dir=str(LOG_BASE_DIR),
        suricata_dirs=data["suricata_dirs"],
        pagination=pagination,
    )


@app.route("/logs/<path:filepath>")
def log_detail(filepath: str) -> str:
    """filepath is in formaat: dirname/filename"""
    all_log_files = get_log_files()
    path = None
    dirname = None
    
    # Zoek het bestand in alle directories
    for dname, dir_files in all_log_files.items():
        if filepath in dir_files:
            path = dir_files[filepath]
            dirname = dname
            break
    
    if not path:
        abort(404, "Logbestand niet gevonden")

    preview = tail_file(path, max_lines=400)
    return render_template(
        "log_detail.html",
        filename=filepath,
        dirname=dirname,
        size=path.stat().st_size,
        updated=datetime.fromtimestamp(path.stat().st_mtime),
        preview=preview,
        log_dir=str(LOG_BASE_DIR),
    )


@app.route("/logs/<path:filepath>/download")
def log_download(filepath: str) -> Response:
    """filepath is in formaat: dirname/filename"""
    all_log_files = get_log_files()
    path = None
    
    # Zoek het bestand in alle directories
    for dname, dir_files in all_log_files.items():
        if filepath in dir_files:
            path = dir_files[filepath]
            break
    
    if not path:
        abort(404, "Logbestand niet gevonden")
    return send_file(path, as_attachment=True)


@app.route("/health")
def health() -> Dict[str, object]:
    suricata_dirs = get_suricata_dirs()
    all_files = get_log_files()
    
    # Tel totaal aantal bestanden
    total_files = sum(len(files) for files in all_files.values())
    
    # Lijst van alle bestanden per directory
    files_by_dir = {}
    for dirname, dir_files in all_files.items():
        files_by_dir[dirname] = [fname for fname in dir_files.keys()]
    
    return {
        "status": "ok",
        "log_base_dir": str(LOG_BASE_DIR),
        "log_base_dir_exists": LOG_BASE_DIR.exists(),
        "suricata_dirs": [d.name for d in suricata_dirs],
        "dir_count": len(suricata_dirs),
        "total_files": total_files,
        "files_by_dir": files_by_dir,
    }


def serialize_alert(alert: Dict[str, object]) -> Dict[str, object]:
    result = {
        "timestamp": alert["timestamp"].isoformat(),
        "message": alert["message"],
        "classification": alert["classification"],
        "priority": alert["priority"],
        "risk": alert["risk"],
        "protocol": alert["protocol"],
        "src": alert["src"],
        "dst": alert["dst"],
        "src_ip": alert.get("src_ip", alert["src"]),
        "src_port": alert.get("src_port", "n/a"),
        "dst_ip": alert.get("dst_ip", alert["dst"]),
        "dst_port": alert.get("dst_port", "n/a"),
        "service": alert.get("service", alert["protocol"]),
        "sid": alert["sid"],
    }
    if "source_dir" in alert:
        result["source_dir"] = alert["source_dir"]
    return result


@app.route("/api/alerts")
def api_alerts() -> Dict[str, object]:
    page = request.args.get("page", default=1, type=int) or 1
    data = gather_dashboard_data()
    pagination = paginate_items(data["alerts"], page, ALERTS_PER_PAGE)
    alerts = [serialize_alert(alert) for alert in pagination["items"]]
    pagination_payload = {k: v for k, v in pagination.items() if k != "items"}
    return {
        "alerts": alerts,
        "stats": data["stats"],
        "pagination": pagination_payload,
    }


if __name__ == "__main__":
    app.run(debug=True)

