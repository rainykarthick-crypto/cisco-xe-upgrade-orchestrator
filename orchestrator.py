#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 Cisco IOS-XE Fleet Upgrade Orchestrator
================================================================================
Upgrades a fleet of Cisco IOS-XE switches (Catalyst 9200/9200L/9200CX/9300/9500)
to IOS-XE 17.18.04 by transferring the .bin via SCP, installing with
``install add`` / ``install activate`` / ``install commit``, reloading and
verifying.

Design rules that this file deliberately obeys (see the project spec):

  * STATE DRIVEN, NEVER TIMER DRIVEN.  Each install-loop iteration reads device
    state, classifies it, issues exactly ONE command, then loops.  The only
    hard time stop is STATE_MACHINE_DEADLINE per device.
  * SESSION CONTINUITY.  The session that carried ``install add`` is the same
    session that runs activate / commit / reload.  A second session opened
    between those phases races the install engine lock.
  * VERSION AWARE DISPATCH.  The activate command form depends on the running
    IOS-XE version (bare form is rejected on >= 17.10).
  * SERVICE LOCKS ON EVERY DEVICE, including devices already on target; every
    temporary change is recorded in state/temp_changes_<RUN_ID>.json and is
    reverted (and verified) at the end of the location run.

Usage
-----
    python orchestrator.py --validate
    python orchestrator.py --check
    python orchestrator.py --locations Jaipur Hyderabad --yes
    python orchestrator.py --hosts SW1=10.0.0.1 --dry-run
    python orchestrator.py --recover

Requires: Python 3.10+, netmiko, paramiko, pscp.exe (PuTTY) in the base dir.
================================================================================
"""

from __future__ import annotations

import argparse
import atexit
import csv
import glob
import hashlib
import inspect
import json
import os
import queue
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from collections import deque
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Optional third party imports.  They are required for a real run, but the
# module must still import cleanly so that --validate / --version work even on
# a workstation where the wheels are not installed yet.
# ---------------------------------------------------------------------------
try:  # pragma: no cover
    import paramiko  # type: ignore
except Exception:  # pragma: no cover
    paramiko = None  # type: ignore

try:  # pragma: no cover
    from netmiko import ConnectHandler  # type: ignore
except Exception:  # pragma: no cover
    ConnectHandler = None  # type: ignore


def tune_paramiko_algorithms() -> Dict[str, Any]:
    """Offer the legacy algorithms that IOS-XE 16.x/17.3 still speak.

    Old Catalyst builds frequently offer only dh-group14-sha1/group1-sha1,
    hmac-sha1 and ssh-rsa.  Newer paramiko releases dropped several of those
    from their default preference lists, which surfaces as
    "no acceptable kex algorithm" / "no acceptable host key" at connect time.

    Every candidate is validated against the algorithm table that this
    paramiko build actually implements, so naming a removed implementation can
    never poison the negotiation.  Attributes whose table is unavailable are
    left at paramiko's own defaults - guessing there would cause hard
    connection failures rather than graceful fallback.
    """
    report: Dict[str, Any] = {"legacy_kex": False, "legacy_key": False,
                              "applied": [], "paramiko": None}
    if paramiko is None:
        return report
    report["paramiko"] = getattr(paramiko, "__version__", "unknown")
    kex = ("curve25519-sha256", "curve25519-sha256@libssh.org",
           "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
           "diffie-hellman-group-exchange-sha256",
           "diffie-hellman-group16-sha512",
           "diffie-hellman-group14-sha256",
           "diffie-hellman-group14-sha1",
           "diffie-hellman-group-exchange-sha1",
           "diffie-hellman-group1-sha1")
    ciphers = ("aes128-ctr", "aes192-ctr", "aes256-ctr",
               "aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
               "aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc")
    macs = ("hmac-sha1", "hmac-sha1-etm@openssh.com", "hmac-sha1-96",
            "hmac-sha2-256", "hmac-sha2-256-etm@openssh.com",
            "hmac-sha2-512", "hmac-sha2-512-etm@openssh.com",
            "hmac-md5", "hmac-md5-96",
            "hmac-ripemd160@openssh.com", "umac-64@openssh.com")
    keys = ("rsa-sha2-512", "rsa-sha2-256", "ssh-rsa")
    transport = getattr(paramiko, "Transport", None)
    if transport is None:
        return report
    plan = (("_preferred_kex", "_kex_info", kex, "legacy_kex",
             ("diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1",
              "diffie-hellman-group-exchange-sha1")),
            ("_preferred_ciphers", "_cipher_info", ciphers, None,
             ("3des-cbc", "aes128-cbc")),
            ("_preferred_macs", "_mac_info", macs, None,
             ("hmac-md5", "hmac-sha1")),
            ("_preferred_keys", "_key_info", keys, "legacy_key", ("ssh-rsa",)))
    for attr, info_attr, wanted, flag, legacy_markers in plan:
        try:
            info = getattr(transport, info_attr, None)
            if not isinstance(info, dict) or not info:
                continue  # cannot verify the names -> keep paramiko defaults
            chosen = [name for name in wanted if name in info]
            if not chosen:
                continue
            setattr(transport, attr, tuple(chosen))
            report["applied"].append("%s=%d" % (attr, len(chosen)))
            if flag and any(marker in chosen for marker in legacy_markers):
                report[flag] = True
        except Exception as exc:
            report["applied"].append("%s failed: %s" % (attr, str(exc)[:60]))
    return report


PARAMIKO_REPORT: Dict[str, Any] = tune_paramiko_algorithms()


# ===========================================================================
#  IDENTITY
# ===========================================================================
VERSION = "1.0.0"
SCRIPT_NAME = "orchestrator.py"
TARGET_VERSION = "17.18.04"

DEFAULT_LOCATIONS = ["Jaipur", "Hyderabad", "Ghaziabad", "KB-Churchgate", "Kolkata"]

# ---------------------------------------------------------------------------
#  Model -> firmware mapping.  ORDER MATTERS: longest prefix first so that
#  "C9200CX"/"C9200L" are matched before the shorter "C9200" prefix.
# ---------------------------------------------------------------------------
MODEL_FIRMWARE_MAP: Tuple[Tuple[str, str, str], ...] = (
    ("C9200CX", "cat9k_lite_iosxe.17.18.04.SPA.bin", "17.18.04"),
    ("C9200L", "cat9k_lite_iosxe.17.18.04.SPA.bin", "17.18.04"),
    ("C9200", "cat9k_lite_iosxe.17.18.04.SPA.bin", "17.18.04"),
    ("C9300", "cat9k_iosxe.17.18.04.SPA.bin", "17.18.04"),
    ("C9500", "cat9k_iosxe.17.18.04.SPA.bin", "17.18.04"),
)

MODEL_FAMILY_MAP: Dict[str, Tuple[str, Optional[str]]] = {
    "C9200CX": ("lite", "_lite_"),
    "C9200L": ("lite", "_lite_"),
    "C9200": ("lite", "_lite_"),
    "C9300": ("full", None),
    "C9500": ("full", None),
}

LARGE_MODEL_PREFIXES = ("C9300", "C9500")

# Errors that must never be retried: retrying makes things worse.
NON_RETRYABLE_PREFIXES = (
    "not_install_mode",
    "insufficient_space",
    "insufficient_space_stack",
    "not priv 15",
    "unsupported model",
    "size mismatch",
    "MD5 mismatch",
    "hash mismatch",
    "shutdown requested",
    "TACACS+ denied",
    "TACACS+ dropped",
    "SSH negotiation failed",
    "host key",
    "firmware mismatch",
    "two committed versions",
    "install_activate FAILED",
    "install_add FAILED",
    "install_commit FAILED",
    "install operation error",
)


# ===========================================================================
#  TUNING CONSTANTS  (every one of these may be overridden from config.json)
# ===========================================================================
TRANSFER_SLOTS = 5
INSTALL_WORKERS = 10
MAX_SAFE_SSH_SESSIONS = 15
LARGE_MODEL_PARALLEL = 3
SERIAL_TRANSFER_LARGE_MODELS = True          # C9300/C9500 run in their own slower phase

USE_PSCP = True
PSCP_TRANSFER_FALLBACK = True
TRANSFER_RETRY_ATTEMPTS = 3
TRANSFER_RETRY_DELAY_SEC = 30
VERIFY_TRANSFER_HASH = True
FIRMWARE_RECHECK_BEFORE_TRANSFER = True
SCP_STALL_TIMEOUT = 600
SCP_SIZE_CHECK_INTERVAL = 90

MIN_FREE_BYTES = 1_000_000_000
EXTRA_HEADROOM_BYTES = 200_000_000
STACK_MEMBER_HEADROOM = 100_000_000

STATE_MACHINE_DEADLINE = 2400                # outer per-device cap, seconds
STATE_POLL_INTERVAL = 15
STATE_MAX_SAME = 40
MAX_ESCALATIONS = 2

PING_TIMEOUT_MS = 2000
PING_DOWN_POLL_SEC = 5
PING_DOWN_TIMEOUT_SEC = 300
PING_UP_POLL_SEC = 10
PING_UP_TIMEOUT_SEC = 900

POST_REBOOT_SSH_WAIT_SEC = 900
POST_REBOOT_SETTLE_SEC = 120
POST_REBOOT_MAX_ATTEMPTS = 30
POST_REBOOT_DELAY_SEC = 30

RECONNECT_MAX_ATTEMPTS = 5
RECONNECT_DELAY_SEC = 30

STALL_DETECT_MIN = 20
MONITOR_INTERVAL = 15

PRESERVE_ROLLBACK = True                     # keep old images in flash
REVERT_TEMP_CONFIG_POST_LOCATION = True
REVERT_MAX_ATTEMPTS = 5
REVERT_RETRY_DELAY_SEC = 20
REVERT_WRITE_MEMORY = True

ABORT_GATE_THRESHOLD = 0.50
ABORT_GATE_MIN_DEVICES = 4

MAX_RETRIES = 2
RETRY_DELAY_SEC = 60

# Model family sanity bounds (megabytes) used by the firmware pre-flight.  A
# violation is reported as a warning, never a hard stop: the real .bin sizes
# move between maintenance releases and a wrong bound must not block a fleet.
FAMILY_SIZE_BOUNDS = {"lite": (300, 800), "full": (1000, 1600)}
FAMILY_SIZE_BOUNDS_STRICT = False

# Retention housekeeping for a long lived orchestrator box.
LOG_MAX_AGE_DAYS = 30
LOG_MAX_SIZE_GB = 10
BACKUP_MAX_FILES = 500
BACKUP_MAX_SIZE_GB = 5

# SSH reachability probing before paying for a full auth handshake.
SSH_PORT_PROBE_SEC = 5
SSH_PORT_PROBE_POLL_SEC = 5

ALLOW_BUNDLE_MODE_CONVERSION = True
SKIP_CONFIG_DRIFT_CHECK = False
PRESAVE_CONFIG = True

# Lines our own temporary changes add; they must not be reported as drift.
DRIFT_NOISE_PREFIXES = (
    "exec-timeout", "ip scp server enable", "ip http server",
    "ip http secure-server", "tftp-server", "no ip http",
    "ip ssh server algorithm", "ip ssh server algorithm kex",
    "boot system flash:packages.conf", "no boot system",
)

POOL_LOCATIONS = True                        # all locations share one worker queue

CLOCK_DRIFT_FIX_SEC = 60
NTP_SERVERS = ("pool.ntp.org", "time.google.com", "time.cloudflare.com",
               "time.windows.com")

# Local image sizes (bytes) keyed by filename; filled by preflight_firmware().
FIRMWARE_SIZES: Dict[str, int] = {}

MODELS_REQUIRING_SSH_TUNE = ("C9300", "C9500")

CHEAP_CRYPTO_TUNING = True
CHEAP_CIPHER = "aes128-ctr"
CHEAP_MAC = "hmac-sha1"
CHEAP_CRYPTO_MIN_VERSION = (17, 10, 0)
CHEAP_CRYPTO_APPLY = ["ip ssh server algorithm encryption aes128-ctr",
                      "ip ssh server algorithm mac hmac-sha1"]
CHEAP_CRYPTO_REVERT = ["no ip ssh server algorithm encryption",
                       "no ip ssh server algorithm mac"]

# Operational extras (not part of the tuning table but useful / overridable)
CONNECT_TIMEOUT_SEC = 30
INSTALL_ADD_DEADLINE_SEC = 2400
ACTIVATE_DEADLINE_SEC = 1200
COMMIT_DEADLINE_SEC = 900
MD5_DEADLINE_SEC = 1800
VERIFY_NO_TEMP_CHANGES = True
PROMPT_QUIET_SEC = 3.0        # silence on the channel that means "prompt returned"

LIVE_LOG_PANEL_PHASES = ("TRANSFER", "INSTALL", "MD5", "REBOOT", "VERIFY")
LIVE_LOG_PANEL_N = 6

ALL_PHASES = ("QUEUE", "PRE-CHECK", "SERVICE-LOCKS", "TRANSFER", "MD5", "INSTALL",
              "REBOOT", "VERIFY", "DONE", "FAILED", "SKIPPED", "STALLED")
PHASE_ORDER = {name: idx for idx, name in enumerate(ALL_PHASES)}
ACTIVE_PHASES = ("PRE-CHECK", "SERVICE-LOCKS", "TRANSFER", "MD5", "INSTALL", "REBOOT", "VERIFY")


# ===========================================================================
#  PATHS  -- update_paths() owns *every* path global (bug B4)
# ===========================================================================
_SCRIPT_DIR = Path(__file__).resolve().parent
_DEFAULT_BASE = Path(os.environ.get("CISCO_UPGRADE_BASE", r"C:\Cisco_Upgrade"))
if not _DEFAULT_BASE.exists() and (_SCRIPT_DIR / "firmware").exists():
    # Running straight out of an unpacked tree: use the script's own folder.
    _DEFAULT_BASE = _SCRIPT_DIR

BASE_DIR: Path = _DEFAULT_BASE
FIRMWARE_DIR: Path = BASE_DIR / "firmware"
LOCATIONS_DIR: Path = BASE_DIR / "locations"
LOG_DIR: Path = BASE_DIR / "logs"
BACKUP_DIR: Path = BASE_DIR / "backups"
REPORT_DIR: Path = BASE_DIR / "reports"
STATE_DIR: Path = BASE_DIR / "state"
CHECKPOINT_DIR: Path = BASE_DIR / "checkpoints"
CONFIG_FILE: Path = BASE_DIR / "config.json"
LOCK_FILE: Path = BASE_DIR / ".upgrade.lock"
PSCP_EXE: Path = BASE_DIR / "pscp.exe"
PLINK_EXE: Path = BASE_DIR / "plink.exe"
_PWFILE_BASE: str = str(Path(tempfile.gettempdir()) / "_pscp_pw_")

# popen flag that keeps a console window from flashing for ping / pscp
NO_WINDOW: int = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0


def update_paths(base_dir: Any) -> None:
    """Point EVERY derived path at *base_dir*.

    Bug B4: the old code only refreshed BASE_DIR, which left the log, state,
    report, backup and firmware paths (plus the lock and password temp files)
    aimed at the original tree.
    """
    global BASE_DIR, FIRMWARE_DIR, LOCATIONS_DIR, LOG_DIR, BACKUP_DIR
    global REPORT_DIR, STATE_DIR, CHECKPOINT_DIR, CONFIG_FILE, LOCK_FILE
    global PSCP_EXE, PLINK_EXE, _PWFILE_BASE

    BASE_DIR = Path(base_dir).expanduser()
    FIRMWARE_DIR = BASE_DIR / "firmware"
    LOCATIONS_DIR = BASE_DIR / "locations"
    LOG_DIR = BASE_DIR / "logs"
    BACKUP_DIR = BASE_DIR / "backups"
    REPORT_DIR = BASE_DIR / "reports"
    STATE_DIR = BASE_DIR / "state"
    CHECKPOINT_DIR = BASE_DIR / "checkpoints"
    CONFIG_FILE = BASE_DIR / "config.json"
    LOCK_FILE = BASE_DIR / ".upgrade.lock"
    PSCP_EXE = BASE_DIR / "pscp.exe"
    PLINK_EXE = BASE_DIR / "plink.exe"
    _PWFILE_BASE = str(Path(tempfile.gettempdir()) / "_pscp_pw_")


# ===========================================================================
#  RUNTIME STATE  (thread shared, always touched under a lock)
# ===========================================================================
RUN_ID: str = time.strftime("%Y%m%d_%H%M%S")
SHUTDOWN_REQ = threading.Event()
SHUTDOWN_COUNT = 0

DEV_STATE: Dict[str, Dict[str, Any]] = {}
STATE_LOCK = threading.RLock()

TEMP_CHANGES: Dict[str, Dict[str, Any]] = {}
TEMP_LOCK = threading.RLock()
STATE_FILES_LOADED: List[str] = []

LOG_LOCK = threading.Lock()
SESSION_SEM = threading.Semaphore(MAX_SAFE_SSH_SESSIONS)
LARGE_SEM = threading.BoundedSemaphore(LARGE_MODEL_PARALLEL)

LIVE_TRANSFER = False
DRY_RUN = False
CHECK_ONLY = False
NO_RECONCILE = False
DASHBOARD_ENABLED = True
CONSOLE_ECHO = True
SERIAL_LARGE = True          # C9300/C9500 transfer in their own slower phase
ALLOW_BUNDLE_CONVERSION = True
VERIFY_HASH = True

ENABLE_PASSWORD: Optional[str] = None
ENABLE_USER: Optional[str] = None

_ANSWERS_DONE: Dict[str, int] = {}


# ===========================================================================
#  LOGGING
# ===========================================================================
def _stamp() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _ensure_dir(path: Path) -> None:
    try:
        path.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def _append(path: Path, text: str) -> None:
    try:
        _ensure_dir(path.parent)
        with LOG_LOCK:
            with open(path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write(text + "\n")
    except Exception:
        pass


def _fmt(level: str, host: str, msg: str) -> str:
    return "%s [%-5s] [%s] %s" % (_stamp(), level, host, msg)


def log_master(level: str, msg: str) -> None:
    _append(LOG_DIR / ("master_%s.log" % RUN_ID), _fmt(level, "master", msg))
    if level in ("WARN", "ERROR"):
        _append(LOG_DIR / "errors.log", _fmt(level, "master", msg))


def dev_log(host: str, level: str, msg: str) -> None:
    _append(LOG_DIR / ("%s.log" % host), _fmt(level, host, msg))
    if level in ("WARN", "ERROR"):
        _append(LOG_DIR / "errors.log", _fmt(level, host, msg))


def log_console(level: str, msg: str) -> None:
    if CONSOLE_ECHO:
        _safe_print("%s %-5s %s" % (time.strftime("%H:%M:%S"), level, msg))


def _safe_print(text: str = "") -> None:
    """Print without ever dying on a legacy console code page."""
    try:
        print(text)
    except UnicodeEncodeError:
        enc = sys.stdout.encoding or "ascii"
        try:
            print(text.encode(enc, "replace").decode(enc, "replace"))
        except Exception:
            pass
    except Exception:
        pass


def _init_stdout() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass


def archive_device_log(host: str) -> None:
    """Keep the previous run's per device log (see ROBUSTNESS section)."""
    src = LOG_DIR / ("%s.log" % host)
    if not src.exists():
        return
    dst = LOG_DIR / "archive" / ("%s_prev_%s.log" % (host, RUN_ID))
    try:
        _ensure_dir(dst.parent)
        shutil.copy2(str(src), str(dst))
        src.unlink()
    except Exception:
        pass


# ===========================================================================
#  LIVE DASHBOARD
# ===========================================================================
def dev_live_log(host: str, line: str) -> None:
    line = (line or "").strip()
    if not line:
        return
    with STATE_LOCK:
        st = DEV_STATE.get(host)
        if st is None:
            st = DEV_STATE[host] = {"phase": "QUEUE", "detail": "", "start": time.time(),
                                    "phase_since": time.time(), "log": deque(maxlen=LIVE_LOG_PANEL_N)}
        st.setdefault("log", deque(maxlen=LIVE_LOG_PANEL_N))
        st["log"].append(line[:118])


def set_phase(host: str, phase: str, detail: str = "", pct: Optional[float] = None) -> None:
    now = time.time()
    with STATE_LOCK:
        st = DEV_STATE.setdefault(host, {})
        st.setdefault("start", now)
        if st.get("phase") != phase:
            st["phase_since"] = now
        st["phase"] = phase
        st["detail"] = detail
        st["updated"] = now
        if pct is not None:
            st["pct"] = pct
        if phase in ("DONE", "FAILED", "SKIPPED"):
            st["finished"] = now


def _progress_bar(pct: float, width: int = 10) -> str:
    pct = max(0.0, min(100.0, float(pct)))
    filled = int(round(width * pct / 100.0))
    return "[%s%s] %5.1f%%" % ("#" * filled, "." * (width - filled), pct)


def _use_ansi() -> bool:
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


_UNICODE_OK: Optional[bool] = None


def _use_unicode() -> bool:
    global _UNICODE_OK
    if _UNICODE_OK is None:
        enc = (sys.stdout.encoding or "ascii").lower()
        _UNICODE_OK = "utf" in enc
    return bool(_UNICODE_OK)


def _dash_rules() -> Tuple[str, str]:
    if _use_unicode():
        return ("\u2500" * 32, "\u2500" * 16)
    return ("-" * 32, "-" * 16)


def render_dashboard(force: bool = False) -> str:
    """Render the dashboard into a string (also used by --check summaries)."""
    now = time.time()
    total = done = failed = active = 0
    rows: List[Tuple[int, str, str, str, str, Tuple[str, ...]]] = []
    with STATE_LOCK:
        for host, st in DEV_STATE.items():
            phase = st.get("phase", "QUEUE")
            if phase in ACTIVE_PHASES and (now - st.get("phase_since", now)) > (STALL_DETECT_MIN * 60):
                phase = "STALLED"
            detail = st.get("detail", "") or ""
            if phase == "TRANSFER" and st.get("pct") is not None:
                detail = _progress_bar(float(st["pct"]))
            elapsed = int(now - st.get("start", now))
            live = tuple(st.get("log") or ())
            rows.append((PHASE_ORDER.get(phase, 99), host, phase, detail[:24], "%ds" % elapsed, live))
            total += 1
            if phase == "DONE":
                done += 1
            elif phase == "FAILED":
                failed += 1
            elif phase in ("STALLED",):
                active += 1
            elif phase not in ("SKIPPED",):
                active += 1
    rows.sort(key=lambda r: (r[0], r[1]))
    lines: List[str] = []
    h1, h2 = _dash_rules()
    lines.append("  %-30s %-16s %-24s %7s" % ("Host", "Phase", "Detail", "Time"))
    lines.append("  %s %s %s %s" % (h1, h2, "-" * 24, "-" * 7))
    for _order, host, phase, detail, elapsed, live in rows:
        lines.append("  %-30s %-16s %-24s %7s" % (host[:30], phase, detail, elapsed))
        if LIVE_TRANSFER and phase in LIVE_LOG_PANEL_PHASES and live:
            for line in live[-LIVE_LOG_PANEL_N:]:
                lines.append("      | %s" % line[:110])
    lines.append("")
    lines.append("  devices=%d  done=%d  failed=%d  in-flight=%d  run=%s  %s"
                 % (total, done, failed, active, RUN_ID, _stamp()))
    return "\n".join(lines)


def dashboard_thread() -> None:
    """Refresh the dashboard every MONITOR_INTERVAL seconds.

    When stdout is a terminal the panel is redrawn in place.  When the output
    is redirected (a log file) the panel is only written when the completion
    counters move or every 15 minutes, so a 500 device run does not produce a
    megabyte of near-identical frames.
    """
    last_print = 0.0
    last_counts: Optional[Tuple[int, int, int]] = None
    while not SHUTDOWN_REQ.is_set():
        try:
            if DASHBOARD_ENABLED:
                body = render_dashboard()
                with STATE_LOCK:
                    counts = (
                        sum(1 for s in DEV_STATE.values() if s.get("phase") == "DONE"),
                        sum(1 for s in DEV_STATE.values() if s.get("phase") == "FAILED"),
                        len(DEV_STATE),
                    )
                if _use_ansi():
                    sys.stdout.write("\033[2J\033[H")
                    _safe_print(body)
                elif counts != last_counts or (time.time() - last_print) > 900:
                    _safe_print(body)
                sys.stdout.flush()
                last_print = time.time()
                last_counts = counts
        except Exception:
            pass
        SHUTDOWN_REQ.wait(MONITOR_INTERVAL)


# ===========================================================================
#  SMALL REGEX / FORMAT HELPERS
# ===========================================================================
_VER3_RE = re.compile(r"\b(\d+)\.(\d+)\.(\d+)\b")
_IOSXE_VER_RE = re.compile(r"Cisco IOS XE Software,\s*Version\s+(\d+)\.(\d+)\.(\d+)")
_ANY_VER_RE = re.compile(r"[Vv]ersion[:\s]+(\d+)\.(\d+)\.(\d+)")

# Bug B11: this list must NOT contain 'failed:\\s*install' -- the switch prints
# "FAILED:" inside its own summary header and that caused false positives.
_FAST_FAIL_RE = re.compile(
    r"(install_activate\s+exit\(\d+\)"
    r"|install_add\s+exit\(\d+\)"
    r"|install_commit\s+exit\(\d+\)"
    r"|install_remove\s+exit\(\d+\)"
    r"|%INSTALL-3-OPERATION_ERROR_MESSAGE"
    r"|%INSTALL-4-INSTALL_BUSY)",
    re.I,
)

# Bug B15: word boundary around eof, never a bare substring test.
_DEAD_SOCKET_RE = re.compile(
    r"(socket is closed|connection reset by peer|connection closed|broken pipe"
    r"|\beof\b|no existing session|transport is closed|ssh session not active"
    r"|not connected|channel closed|10054|10060|10053|paramiko\.ssh_exception)",
    re.I,
)

# TACACS+ command authorization denies privileged commands; the session is
# still usable for reads, so these must not be mistaken for "not priv 15".
_AUTHZ_FAIL_MARKERS = (
    "% authorization failed",
    "authorization failed for user",
    "command authorization failed",
    "command not authorized",
    "% authorization denied",
)

_PROMPT_TAIL_RE = re.compile(r"(?:^|\n)\s*[\w\-\./()\[\]:]{1,60}[#>]\s*$")
_CONFIRM_RE = re.compile(r"\[(?:confirm|y/n|yes/no)\]", re.I)
_SAVE_RE = re.compile(r"\[(?:yes/no|y/n)\]\s*$", re.I)
_YN_RE = re.compile(r"\[(?:y/n|yes/no|confirm)\]", re.I)
_ACTIVATE_REJECT_RE = re.compile(
    r"(issu keyword|Invalid input|%\s*Invalid|rejected|not supported"
    r"|%INSTALL-3-OPERATION_ERROR|incompatible)",
    re.I,
)


def _trim1200(text: str) -> str:
    """Bug B12: parsing buffers are trimmed to 1200 chars, not 4000."""
    return (text or "")[-1200:]


def _ver_tuple(ver: Any) -> Tuple[int, int, int]:
    if ver is None:
        return (0, 0, 0)
    if isinstance(ver, (tuple, list)) and len(ver) >= 3:
        try:
            return (int(ver[0]), int(ver[1]), int(ver[2]))
        except Exception:
            return (0, 0, 0)
    m = _VER3_RE.search(str(ver))
    if not m:
        return (0, 0, 0)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def _ver_str(ver: Any) -> str:
    t = _ver_tuple(ver)
    if t == (0, 0, 0):
        return str(ver or "")
    return "%d.%d.%d" % t


def _is_dead_socket_error(text: Any) -> bool:
    if not text:
        return False
    return bool(_DEAD_SOCKET_RE.search(str(text)))


def parse_running_version(out: str) -> str:
    m = _IOSXE_VER_RE.search(out or "")
    if not m:
        m = _ANY_VER_RE.search(out or "")
    if not m:
        return ""
    return "%s.%s.%s" % (m.group(1), m.group(2), m.group(3))


# ---------------------------------------------------------------------------
#  install-summary parsing  (bug B18: six different output shapes)
# ---------------------------------------------------------------------------
_STATUS_WORDS = {
    "c": "C", "committed": "C", "commit": "C", "committed.": "C",
    "a": "A", "active": "A", "activated": "A", "activate": "A",
    "u": "U", "uncommitted": "U", "pending": "U", "pending-commit": "U",
    "i": "I", "inactive": "I", "deactivated": "I",
}
_STATUS_RANK = {"C": 3, "A": 2, "U": 1, "I": 0}


def _normalise_status(raw: Any) -> str:
    """'(C)' / '[C]' / 'Active, Committed' -> single letter status."""
    if raw is None:
        return "?"
    text = str(raw).strip().strip("()[]{}<>,;: \t\"'")
    if not text:
        return "?"
    token = re.split(r"[\s,;/|]+", text.strip())[0].strip("()[]{}<>,;:.!\"'")
    return _STATUS_WORDS.get(token.lower(), "?")


def _status_tokens(line: str) -> List[str]:
    """Every recognised status token on one line, normalised."""
    found: List[str] = []
    for token in re.split(r"[\s,;/|]+", line or ""):
        bare = token.strip().strip("()[]{}<>,;:.\"'")
        if not bare:
            continue
        st = _STATUS_WORDS.get(bare.lower())
        if st:
            found.append(st)
    return found


def _pick_status(tokens: List[str]) -> str:
    best = "?"
    for tok in tokens:
        if _STATUS_RANK.get(tok, -1) > _STATUS_RANK.get(best, -1):
            best = tok
    return best


def _parse_install_summary(out: str) -> Dict[str, str]:
    """Parse ``show install summary`` into ``{version: single_letter_status}``.

    Handles, at minimum:
        "  IMG  C  17.18.04"                      (row)
        "IMG: flash:..bin" / "Version : X" / "Status : C"   (multi block)
        "17.18.04   Active, Committed"            (table)
        "Version:17.18.04" / "Status: Active"     (no space)
        "17.18.04   Inactive"                     (word form)
        "(C)" / "[C]"                             (bracketed)
    """
    result: Dict[str, str] = {}
    pending_ver: Optional[str] = None
    for raw in (out or "").splitlines():
        line = raw.strip().strip("|")
        if not line or set(line) <= set("-=+ "):
            continue
        low = line.lower()

        m = re.match(r"^(?:version|ver)\s*[:=]\s*(\d+\.\d+\.\d+)", low)
        if m:
            pending_ver = m.group(1)
            continue

        m = re.match(r"^(?:status|state)\s*[:=]\s*(.+)$", low)
        if m:
            status = _normalise_status(m.group(1))
            ver = pending_ver
            if ver is None:
                vm = _VER3_RE.search(line)
                ver = vm.group(0) if vm else None
            if ver and status != "?":
                prev = result.get(ver)
                if prev is None or _STATUS_RANK.get(status, -1) >= _STATUS_RANK.get(prev, -1):
                    result[ver] = status
            continue

        vmatch = _VER3_RE.search(line)
        stats = _status_tokens(line)
        if vmatch and stats:
            ver = vmatch.group(0)
            status = _pick_status(stats)
            prev = result.get(ver)
            if prev is None or _STATUS_RANK.get(status, -1) >= _STATUS_RANK.get(prev, -1):
                result[ver] = status
            pending_ver = ver
        elif vmatch:
            pending_ver = vmatch.group(0)
        elif stats and pending_ver and len(line.split()) <= 3:
            # Multi-block form: a bare status word such as "C" or "(C)" on its
            # own line belongs to the version announced just above it.  Longer
            # lines are column headers ("Active  Package  Type  State") and are
            # ignored so they cannot be mistaken for a status.
            status = _pick_status(stats)
            prev = result.get(pending_ver)
            if prev is None or _STATUS_RANK.get(status, -1) >= _STATUS_RANK.get(prev, -1):
                result[pending_ver] = status
    return result


def _sum_status_for(summary: Dict[str, str], target_ver: str) -> Optional[str]:
    """Status of *target_ver* in a parsed summary, or None.  Exact compare."""
    if not summary:
        return None
    want = _ver_tuple(target_ver)
    for ver, status in summary.items():
        if _ver_tuple(ver) == want:
            return status
    return None


def summary_committed_on_target(summary: Dict[str, str], target_ver: str) -> bool:
    """Bug B13: never substring-match versions here.

    Exactly one entry, exactly the target version, status 'C'.
    """
    if not summary or len(summary) != 1:
        return False
    ver, status = next(iter(summary.items()))
    return _ver_tuple(ver) == _ver_tuple(target_ver) and status == "C"


# ===========================================================================
#  VERSION AWARE COMMAND DISPATCH  (design rule P3)
# ===========================================================================
def classify_install_syntax(ver_tuple: Any) -> Dict[str, Any]:
    """Pick the activate form that this IOS-XE build accepts.

      < 17.3.0   -> bare ``install activate``
      17.3-17.6  -> ``install activate file flash:X``
      17.6-17.9  -> either form works
      >= 17.10   -> ``install activate file flash:X`` (bare rejected)
    """
    ver = _ver_tuple(ver_tuple)
    if ver < (17, 3, 0):
        form = "bare"
    elif ver < (17, 6, 0):
        form = "file"
    elif ver < (17, 10, 0):
        form = "either"
    else:
        form = "file"
    return {
        "activate_form": form,
        "add_syntax": "install add file flash:%s",
        "supports_issu": ver >= (17, 3, 0),
        "version_str": _ver_str(ver) if ver != (0, 0, 0) else "",
    }


def build_activate_cmds(fw_file: str, syntax: Dict[str, Any]) -> List[str]:
    """Best-first list of activate commands for the given syntax decision."""
    file_form = "install activate file flash:%s" % fw_file
    bare_form = "install activate"
    form = (syntax or {}).get("activate_form", "file")
    if form == "bare":
        return [bare_form]
    if form == "either":
        return [file_form, bare_form]
    return [file_form]


# ===========================================================================
#  SESSION PLUMBING
# ===========================================================================
def _session_slot(acquire: bool, timeout: float = 0.0) -> bool:
    """Keep the fleet under MAX_SAFE_SSH_SESSIONS concurrent SSH channels."""
    if acquire:
        if timeout and timeout > 0:
            return SESSION_SEM.acquire(timeout=timeout)
        SESSION_SEM.acquire()
        return True
    try:
        SESSION_SEM.release()
    except Exception:
        pass
    return True


def do_connect(ip: str, host: str, user: str, pw: str, enable_pw: str = "",
               fast: bool = False, timeout: int = CONNECT_TIMEOUT_SEC) -> Any:
    """Open one netmiko session and install a paramiko keepalive.

    Bug B2: paramiko's SSHClient has no public ``transport`` attribute, so the
    old reflective attribute lookup silently did nothing and mid-install
    disconnects were never prevented.  We now call ``get_transport()`` on the
    underlying client and set a 30 s keepalive.
    """
    if ConnectHandler is None:
        raise RuntimeError("netmiko is not installed; pip install netmiko")
    _session_slot(True, timeout=300)
    try:
        params = dict(
            device_type="cisco_ios",
            host=ip,
            username=user,
            password=pw,
            secret=enable_pw or pw,
            port=22,
            timeout=timeout,
            conn_timeout=timeout,
            auth_timeout=timeout,
            banner_timeout=timeout,
            fast_cli=bool(fast),
            global_delay_factor=1.0,
        )
        client = ConnectHandler(**params)
    except Exception:
        _session_slot(False)
        raise

    transport = None
    try:
        transport = client.remote_conn.get_transport()
    except Exception:
        transport = None
    if transport is None:
        try:
            transport = client.get_transport()
        except Exception:
            transport = None
    if transport is not None:
        try:
            transport.set_keepalive(30)
        except Exception:
            pass

    try:
        client.enable()
    except Exception:
        pass
    dev_log(host, "INFO", "ssh session established to %s" % ip)
    return client


def _disconnect(conn: Any, release: bool = True) -> None:
    if conn is None:
        return
    try:
        conn.disconnect()
    except Exception:
        pass
    if release:
        _session_slot(False)


def _session_is_alive(conn: Any) -> bool:
    """Bug B5: a single 0.3 s read produced false negatives while the switch
    was busy installing.  Loop for up to 3.0 s before declaring death.

    Prefers the framework's liveness probe; if this netmiko build does not
    expose one, fall back to a plain write/read round trip so the check still
    works on any transport object.
    """
    if conn is None:
        return False
    probe = getattr(conn, "is_alive", None)
    deadline = time.time() + 3.0
    while time.time() < deadline:
        try:
            if callable(probe):
                if probe():
                    return True
            else:
                conn.write_channel("\n")
                if conn.read_channel():
                    return True
        except Exception as exc:
            if _is_dead_socket_error(str(exc)):
                return False
        time.sleep(0.3)
    return False


def robust_reconnect(host: str, ip: str, user: str, pw: str, enable_pw: str = "",
                     max_attempts: int = RECONNECT_MAX_ATTEMPTS,
                     delay: int = RECONNECT_DELAY_SEC) -> Any:
    for attempt in range(1, max(1, int(max_attempts)) + 1):
        if SHUTDOWN_REQ.is_set():
            return None
        try:
            conn = do_connect(ip, host, user, pw, enable_pw)
            dev_log(host, "OK", "reconnect attempt %d succeeded" % attempt)
            return conn
        except Exception as exc:
            dev_log(host, "WARN", "reconnect attempt %d/%d failed: %s"
                    % (attempt, max_attempts, exc))
            if _is_dead_socket_error(str(exc)) or "authentication" in str(exc).lower():
                pass
        SHUTDOWN_REQ.wait(delay)
    return None


def _fresh_conn(old: Any, host: str, ip: str, user: str, pw: str,
                enable_pw: str = "", attempts: int = 3, delay: int = 15) -> Any:
    """Drop *old* (releasing its session slot) and return a new session."""
    _disconnect(old)
    return robust_reconnect(host, ip, user, pw, enable_pw, attempts, delay)


def _poll_read(conn: Any) -> str:
    """Non blocking-ish channel read used by all long command loops."""
    try:
        data = conn.read_channel()
        return data or ""
    except Exception as exc:
        if _is_dead_socket_error(str(exc)):
            raise
        return ""


def _last_line(buf: str) -> str:
    if not buf or not buf.strip():
        return ""
    return buf.rstrip().splitlines()[-1].strip()


def _drain_and_answer_prompts(conn: Any, max_seconds: float = 30.0) -> str:
    """Read the channel until the device prompt comes back.

    Bug B16: return as soon as ``#``/``>`` ends the last line with no pending
    y/n, instead of burning the whole max_seconds budget.
    """
    deadline = time.time() + max_seconds
    buf = ""
    answered: Dict[str, int] = {}
    while time.time() < deadline:
        if SHUTDOWN_REQ.is_set():
            break
        try:
            data = _poll_read(conn)
        except Exception:
            break
        if data:
            buf = (buf + data)[-4000:]
        line = _last_line(buf)
        if _YN_RE.search(line):
            answered[line] = answered.get(line, 0) + 1
            if answered[line] <= 2:
                try:
                    conn.write_channel("y\n" if "yes/no" in line.lower() else "\n")
                except Exception:
                    pass
                time.sleep(0.5)
                continue
        if line and _PROMPT_TAIL_RE.search(buf) and not _YN_RE.search(line):
            return buf
        time.sleep(0.4)
    return buf


def _sh(conn: Any, cmd: str, read_timeout: int = 60, host: str = "") -> str:
    """Short read-only command (``show ...``), safe against a dead session."""
    if conn is None:
        return ""
    try:
        out = conn.send_command(cmd, strip_prompt=True, strip_command=True,
                                read_timeout=read_timeout)
        return out or ""
    except Exception as exc:
        if host:
            dev_log(host, "WARN", "command failed (%s): %s" % (cmd, exc))
        return ""


def _send_long(conn: Any, cmd: str, deadline_sec: int = 300, host: str = "",
               answer_confirm: bool = True) -> Tuple[str, str]:
    """Write one command and poll until the prompt returns.

    Returns ``(tail_of_buffer, reason)`` with reason in
    ``{"done", "fastfail", "timeout", "dead", "shutdown"}``.

    The buffer handed back is trimmed to 1200 chars (bug B12) so stale text can
    never re-trigger the fast-fail detector, and the loop is shutdown aware so
    Ctrl+C stays responsive during a ten minute ``install add``.
    """
    if conn is None:
        return "", "dead"
    try:
        conn.write_channel(cmd + "\n")
    except Exception:
        return "", "dead"
    dev_log(host, "CMD", cmd) if host else None
    deadline = time.time() + max(5, int(deadline_sec))
    buf = ""
    answered: Dict[str, int] = {}
    last_data = time.time()
    while time.time() < deadline:
        if SHUTDOWN_REQ.is_set():
            return _trim1200(buf), "shutdown"
        try:
            data = _poll_read(conn)
        except Exception:
            return _trim1200(buf), "dead"
        if data:
            buf += data
            buf = buf[-4000:]
            last_data = time.time()
            if host:
                for line in data.splitlines():
                    if line.strip():
                        dev_live_log(host, line.strip())
        tail = _trim1200(buf)
        if _FAST_FAIL_RE.search(tail):
            return tail, "fastfail"
        if answer_confirm:
            line = _last_line(buf)
            if line and answered.get(line, 0) < 2:
                # "install remove inactive" style prompts want an explicit
                # y/yes; a bare "[confirm]" wants a newline.
                if _SAVE_RE.search(line):
                    answered[line] = answered.get(line, 0) + 1
                    try:
                        conn.write_channel("y\n")
                    except Exception:
                        pass
                    last_data = time.time()
                    time.sleep(0.5)
                    continue
                if _CONFIRM_RE.search(line):
                    answered[line] = answered.get(line, 0) + 1
                    try:
                        conn.write_channel("\n")
                    except Exception:
                        pass
                    last_data = time.time()
                    time.sleep(0.5)
                    continue
        if _PROMPT_TAIL_RE.search(buf) and (time.time() - last_data) >= PROMPT_QUIET_SEC:
            return tail, "done"
        time.sleep(0.5)
    return _trim1200(buf), "timeout"


def _issue_reload(conn: Any, host: str) -> bool:
    """Ask the switch to reload and answer its confirmation prompts."""
    dev_log(host, "STEP", "issuing reload")
    try:
        conn.write_channel("reload\n")
    except Exception:
        return False
    deadline = time.time() + 180
    buf = ""
    while time.time() < deadline:
        try:
            data = _poll_read(conn)
        except Exception:
            return True
        if data:
            buf = (buf + data)[-2000:]
            for line in data.splitlines():
                if line.strip():
                    dev_live_log(host, line.strip())
        low = buf.lower()
        if "aborted" in low or "not reload" in low:
            dev_log(host, "WARN", "reload was refused by the device")
            return False
        if re.search(r"\[confirm\]", buf, re.I):
            try:
                conn.write_channel("\n")
            except Exception:
                pass
            buf += "\n"
        if re.search(r"\[yes/no\]|\[y/n\]", buf, re.I):
            try:
                conn.write_channel("yes\n")
            except Exception:
                pass
            buf += "\n"
        if re.search(r"(reloading|restarting|%SYS-5-RELOAD|connection.*closed|shutting down)", buf, re.I):
            return True
        time.sleep(0.5)
    return True


# ===========================================================================
#  ICMP / CLOCK
# ===========================================================================
def _ping_once(ip: str, timeout_ms: int = PING_TIMEOUT_MS) -> bool:
    if os.name == "nt":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=15,
                              creationflags=NO_WINDOW)
        text = (proc.stdout or b"").decode("utf-8", "replace").lower()
        if os.name == "nt":
            # Windows ping exits 0 for "Destination host unreachable" replies.
            return "ttl=" in text and "unreachable" not in text \
                and "timed out" not in text
        return proc.returncode == 0
    except Exception:
        return False


def ssh_port_open(ip: str, timeout: int = SSH_PORT_PROBE_SEC) -> bool:
    """Cheap TCP/22 probe - far faster than letting netmiko time out."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, 22)) == 0
    except OSError:
        return False


def ssh_reachable(ip: str, attempts: int = 2, gap: float = 2.0) -> bool:
    """Two TCP/22 probes before declaring a device unreachable.

    A single refused probe is not proof: a switch that is mid-boot or busy
    installing can drop one SYN.  Requiring two failures keeps the fast path
    without ever skipping a device that is actually answering.
    """
    for index in range(max(1, attempts)):
        if ssh_port_open(ip):
            return True
        if index + 1 < max(1, attempts):
            time.sleep(gap)
    return False


def _wait_ping(ip: str, expect_up: bool, timeout: int, poll: int, host: str = "") -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if SHUTDOWN_REQ.is_set():
            return False
        up = _ping_once(ip)
        if up == expect_up:
            return True
        SHUTDOWN_REQ.wait(poll)
    return False


def _fetch_reference_utc() -> Optional[datetime]:
    """UDP NTP query, with server fallback.

    Every socket is closed in a ``finally`` block so a failed time source can
    never leak a descriptor, and a working source is returned as soon as one
    answers.
    """
    for server in NTP_SERVERS:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3.0)
            packet = b"\x1b" + 47 * b"\0"
            s.sendto(packet, (server, 123))
            data, _ = s.recvfrom(1024)
            if len(data) < 48:
                continue
            seconds = struct.unpack("!I", data[40:44])[0]
            frac = struct.unpack("!I", data[44:48])[0]
            epoch = seconds - 2208988800
            if epoch <= 0:
                continue
            return datetime.fromtimestamp(epoch + (frac / 2.0 ** 32), tz=timezone.utc)
        except Exception:
            continue
        finally:
            try:
                if s is not None:
                    s.close()
            except Exception:
                pass
    return None


_TIMEZONE_RE = re.compile(
    r"(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?\s+(\S+)\s+(\w{3})\s+(\w{3})\s+(\d{1,2})\s+(\d{4})")

_MONTHS = {name: idx for idx, name in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def _parse_show_clock(out: str) -> Optional[Dict[str, Any]]:
    """Parse ``show clock`` -> naive UTC datetime + timezone text."""
    m = _TIMEZONE_RE.search(out or "")
    if not m:
        return None
    month = _MONTHS.get(m.group(6).capitalize())
    if not month:
        return None
    try:
        dt = datetime(int(m.group(8)), month, int(m.group(7)),
                      int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None
    return {"tz_text": m.group(4), "dt": dt, "raw": m.group(0).strip()}


def _tz_is_utcish(tz_text: str) -> bool:
    tz = (tz_text or "").upper()
    if tz in ("UTC", "GMT", "Z", "UT"):
        return True
    return bool(re.match(r"^[+-]\d{1,2}(:\d{2})?$", tz))


def fix_clock_drift(conn: Any, host: str) -> bool:
    """NTP based drift correction; skipped when the device is not in UTC/GMT."""
    try:
        clock_out = _sh(conn, "show clock", 30, host)
        parsed = _parse_show_clock(clock_out)
        if not parsed:
            return False
        if not _tz_is_utcish(parsed["tz_text"]):
            dev_log(host, "INFO", "clock drift check skipped (timezone %s)" % parsed["tz_text"])
            return False
        ref = _fetch_reference_utc()
        if ref is None:
            dev_log(host, "WARN", "clock drift check skipped (no NTP reference)")
            return False
        drift = abs((ref.replace(tzinfo=None) - parsed["dt"]).total_seconds())
        if drift < CLOCK_DRIFT_FIX_SEC:
            return False
        stamp = ref.strftime("%H:%M:%S %d %b %Y")
        out, why = _send_long(conn, "clock set %s" % stamp, 60, host)
        dev_log(host, "OK", "clock drift %.0fs corrected to %s" % (drift, stamp))
        return why in ("done", "timeout")
    except Exception as exc:
        dev_log(host, "WARN", "clock drift check failed: %s" % exc)
        return False


# ===========================================================================
#  TEMP CHANGE TRACKING  (design rule P5)
# ===========================================================================
def temp_state_path(run_id: Optional[str] = None) -> Path:
    return STATE_DIR / ("temp_changes_%s.json" % (run_id or RUN_ID))


def track_temp_change(host: str, ctype: str, ip: str = "", **details: Any) -> None:
    """Record one temporary change and flush it to disk immediately."""
    with TEMP_LOCK:
        entry = TEMP_CHANGES.setdefault(host, {"ip": ip, "changes": []})
        if ip:
            entry["ip"] = ip
        entry["changes"].append({"type": ctype, "details": details,
                                 "ts": time.strftime("%Y-%m-%d %H:%M:%S")})
    save_temp_changes()
    dev_log(host, "INFO", "temp change recorded: %s %s" % (ctype, details))


def save_temp_changes(path: Optional[Path] = None) -> None:
    target = path or temp_state_path()
    with TEMP_LOCK:
        payload = json.dumps(TEMP_CHANGES, indent=2, sort_keys=True, default=str)
    try:
        _ensure_dir(target.parent)
        tmp = str(target) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(payload)
        os.replace(tmp, str(target))
    except Exception as exc:
        log_master("ERROR", "could not persist temp changes: %s" % exc)


def load_state_for_recovery() -> int:
    """Read every ``state/temp_changes_*.json`` written by earlier runs.

    Bug B7: this is called exactly ONCE, from main(), so state belonging to
    location A can never leak into location B.
    """
    loaded = 0
    files = sorted(glob.glob(str(STATE_DIR / "temp_changes_*.json")))
    with TEMP_LOCK:
        for path in files:
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except Exception as exc:
                log_master("WARN", "unreadable state file %s: %s" % (path, exc))
                continue
            if not isinstance(data, dict):
                continue
            for host, entry in data.items():
                if not isinstance(entry, dict):
                    continue
                current = TEMP_CHANGES.setdefault(host, {"ip": entry.get("ip", ""), "changes": []})
                if entry.get("ip"):
                    current["ip"] = entry["ip"]
                for change in entry.get("changes", []):
                    if change not in current["changes"]:
                        current["changes"].append(change)
                loaded += 1
            if path not in STATE_FILES_LOADED:
                STATE_FILES_LOADED.append(path)
    if loaded:
        log_master("WARN", "recovered pending temp changes for %d host(s) from prior runs" % loaded)
    return loaded


def pending_temp_changes() -> Dict[str, List[Dict[str, Any]]]:
    with TEMP_LOCK:
        return {host: list(entry.get("changes", []))
                for host, entry in TEMP_CHANGES.items() if entry.get("changes")}


def clear_temp_changes(host: str) -> None:
    with TEMP_LOCK:
        entry = TEMP_CHANGES.get(host)
        if entry:
            entry["changes"] = []
    save_temp_changes()


# ===========================================================================
#  SERVICE LOCKS  (design rule P4)
# ===========================================================================
def apply_service_locks(conn: Any, host: str) -> Dict[str, Any]:
    """Disable every management plane service that can interrupt an install.

    Always applied, on every device, including devices already on target:
      * ``ip http server``        -> disabled (original state recorded)
      * ``ip https server``       -> disabled (original state recorded)
      * ``tftp-server ...``       -> every entry removed (entries recorded)
      * ``ip scp server enable``  -> enabled (we need SCP for the transfer)
    """
    applied: Dict[str, Any] = {}
    run = _sh(conn, "show running-config | include ^ip http", 60, host)
    was_http = bool(re.search(r"^\s*ip http server\s*$", run, re.M))
    was_https = bool(re.search(r"^\s*ip http secure-server\s*$|^\s*ip https server\s*$", run, re.M))
    applied["http_server"] = {"was_enabled": was_http}
    applied["https_server"] = {"was_enabled": was_https}

    if was_http:
        _send_long(conn, "configure terminal", 30, host, answer_confirm=False)
        _send_long(conn, "no ip http server", 30, host, answer_confirm=False)
        _send_long(conn, "end", 30, host, answer_confirm=False)
        track_temp_change(host, "http_server", was_enabled=True)
    else:
        track_temp_change(host, "http_server", was_enabled=False)

    if was_https:
        _send_long(conn, "configure terminal", 30, host, answer_confirm=False)
        _send_long(conn, "no ip http secure-server", 30, host, answer_confirm=False)
        _send_long(conn, "end", 30, host, answer_confirm=False)
        track_temp_change(host, "https_server", was_enabled=True)
    else:
        track_temp_change(host, "https_server", was_enabled=False)

    tftp_out = _sh(conn, "show running-config | include ^tftp-server", 60, host)
    was_entries = [ln.strip() for ln in (tftp_out or "").splitlines() if ln.strip().startswith("tftp-server")]
    applied["tftp_server"] = {"was_entries": was_entries}
    if was_entries:
        _send_long(conn, "configure terminal", 30, host, answer_confirm=False)
        for entry in was_entries:
            _send_long(conn, "no %s" % entry, 30, host, answer_confirm=False)
        _send_long(conn, "end", 30, host, answer_confirm=False)
        track_temp_change(host, "tftp_server", was_entries=was_entries)
    else:
        track_temp_change(host, "tftp_server", was_entries=[])

    scp_out = _sh(conn, "show running-config | include ^ip scp server", 60, host)
    was_scp = bool(re.search(r"^\s*ip scp server enable\s*$", scp_out, re.M))
    applied["scp_server"] = {"was_enabled": was_scp}
    if not was_scp:
        _send_long(conn, "configure terminal", 30, host, answer_confirm=False)
        _send_long(conn, "ip scp server enable", 30, host, answer_confirm=False)
        _send_long(conn, "end", 30, host, answer_confirm=False)
        track_temp_change(host, "scp_server", was_enabled=False)
    else:
        track_temp_change(host, "scp_server", was_enabled=True)

    return applied


def apply_exec_timeout(conn: Any, host: str) -> None:
    """Stop the vty from timing out mid install (recorded as a temp change)."""
    original = ""
    try:
        out = _sh(conn, "show running-config | section line vty", 60, host)
        m = re.search(r"exec-timeout\s+(\d+\s+\d+)", out or "")
        original = m.group(1) if m else "10 0"
    except Exception:
        original = "10 0"
    _send_long(conn, "configure terminal", 30, host, answer_confirm=False)
    _send_long(conn, "line vty 0 15", 30, host, answer_confirm=False)
    _send_long(conn, "exec-timeout 0 0", 30, host, answer_confirm=False)
    _send_long(conn, "end", 30, host, answer_confirm=False)
    track_temp_change(host, "exec_timeout", original=original, applied="0 0")


def ssh_tune(conn: Any, host: str, model: str = "") -> None:
    """Large chassis drop SSH sessions unless the key exchange is cheapened."""
    if not any((model or "").upper().startswith(p) for p in MODELS_REQUIRING_SSH_TUNE):
        return
    _send_long(conn, "configure terminal", 30, host, answer_confirm=False)
    _send_long(conn, "ip ssh server algorithm kex diffie-hellman-group-exchange-sha1",
               30, host, answer_confirm=False)
    _send_long(conn, "ip ssh server algorithm mac hmac-sha1", 30, host, answer_confirm=False)
    _send_long(conn, "end", 30, host, answer_confirm=False)
    track_temp_change(host, "ssh_tune", model=model)


def cheap_crypto(conn: Any, host: str, version: str = "") -> None:
    """Apply the cheaper crypto suite on >= 17.10 where AES-GCM stalls."""
    if not CHEAP_CRYPTO_TUNING:
        return
    if _ver_tuple(version) < CHEAP_CRYPTO_MIN_VERSION:
        return
    _send_long(conn, "configure terminal", 30, host, answer_confirm=False)
    for cmd in CHEAP_CRYPTO_APPLY:
        _send_long(conn, cmd, 30, host, answer_confirm=False)
    _send_long(conn, "end", 30, host, answer_confirm=False)
    track_temp_change(host, "cheap_crypto", applied=list(CHEAP_CRYPTO_APPLY),
                      cipher=CHEAP_CIPHER, mac=CHEAP_MAC)


def revert_temp_config(conn: Any, host: str) -> Tuple[int, int]:
    """Undo every temporary change for *host*.  Returns (ok_count, fail_count).

    Inverse of apply_service_locks() + apply_exec_timeout() + ssh_tune() +
    cheap_crypto(); idempotent, so it is safe on a device that never had the
    change applied (for example after a reload wiped it).
    """
    ok = 0
    fail = 0
    with TEMP_LOCK:
        entry = TEMP_CHANGES.get(host, {})
        changes = list(entry.get("changes", []))
    if not changes:
        return (0, 0)
    if conn is None:
        return (0, len(changes))

    def _do(cmds: List[str]) -> bool:
        good = True
        for cmd in cmds:
            _out, why = _send_long(conn, cmd, 60, host, answer_confirm=False)
            if why in ("dead", "shutdown"):
                good = False
                break
        return good

    for change in changes:
        ctype = change.get("type")
        details = change.get("details", {}) or {}
        try:
            if ctype == "http_server":
                if details.get("was_enabled"):
                    good = _do(["configure terminal", "ip http server", "end"])
                    (ok, fail) = (ok + 1, fail) if good else (ok, fail + 1)
            elif ctype == "https_server":
                if details.get("was_enabled"):
                    good = _do(["configure terminal", "ip http secure-server", "end"])
                    (ok, fail) = (ok + 1, fail) if good else (ok, fail + 1)
            elif ctype == "tftp_server":
                entries = details.get("was_entries") or []
                if entries:
                    cmds = ["configure terminal"] + list(entries) + ["end"]
                    good = _do(cmds)
                    (ok, fail) = (ok + 1, fail) if good else (ok, fail + 1)
            elif ctype == "scp_server":
                if not details.get("was_enabled"):
                    good = _do(["configure terminal", "no ip scp server enable", "end"])
                    (ok, fail) = (ok + 1, fail) if good else (ok, fail + 1)
            elif ctype == "exec_timeout":
                original = details.get("original") or "10 0"
                good = _do(["configure terminal", "line vty 0 15",
                            "exec-timeout %s" % original, "end"])
                (ok, fail) = (ok + 1, fail) if good else (ok, fail + 1)
            elif ctype == "ssh_tune":
                good = _do(["configure terminal", "no ip ssh server algorithm mac hmac-sha1",
                            "no ip ssh server algorithm kex diffie-hellman-group-exchange-sha1",
                            "end"])
                (ok, fail) = (ok + 1, fail) if good else (ok, fail + 1)
            elif ctype == "cheap_crypto":
                good = _do(["configure terminal"] + list(CHEAP_CRYPTO_REVERT) + ["end"])
                (ok, fail) = (ok + 1, fail) if good else (ok, fail + 1)
            else:
                dev_log(host, "WARN", "unknown temp change type %s" % ctype)
        except Exception as exc:
            fail += 1
            dev_log(host, "WARN", "revert of %s failed: %s" % (ctype, exc))

    if fail == 0:
        clear_temp_changes(host)
        dev_log(host, "OK", "temp config reverted (%d item(s))" % ok)
        if REVERT_WRITE_MEMORY and ok:
            _send_long(conn, "write memory", 120, host)
    else:
        dev_log(host, "WARN", "temp config revert incomplete: ok=%d fail=%d" % (ok, fail))
    return (ok, fail)


def revert_temp_config_with_retry(host: str, ip: str, user: str, pw: str,
                                  enable_pw: str = "") -> Tuple[int, int, bool]:
    """Revert with reconnect retries; used at the end of a location run."""
    last = (0, 0)
    for attempt in range(1, REVERT_MAX_ATTEMPTS + 1):
        if SHUTDOWN_REQ.is_set():
            return last[0], last[1], False
        conn = None
        try:
            conn = do_connect(ip, host, user, pw, enable_pw, fast=True)
            ok, fail = revert_temp_config(conn, host)
            last = (ok, fail)
            if fail == 0:
                return ok, fail, True
            dev_log(host, "WARN", "revert attempt %d/%d incomplete" % (attempt, REVERT_MAX_ATTEMPTS))
        except Exception as exc:
            dev_log(host, "WARN", "revert attempt %d/%d connect failed: %s"
                    % (attempt, REVERT_MAX_ATTEMPTS, exc))
        finally:
            _disconnect(conn)
        SHUTDOWN_REQ.wait(REVERT_RETRY_DELAY_SEC)
    return last[0], last[1], False


def verify_no_temp_changes(devices: List[Any], user: str, pw: str, location_name: str) -> Dict[str, Any]:
    """Confirm nothing temporary is left behind on any device of the location.

    On-target devices are included: they received the same service locks, so
    they must be reverted and verified too (incl. on-target).
    """
    report: Dict[str, Any] = {}
    leftovers = 0
    for dev in devices:
        host = getattr(dev, "hostname", str(dev))
        with TEMP_LOCK:
            entry = TEMP_CHANGES.get(host, {})
            changes = list(entry.get("changes", []))
        if changes:
            leftovers += 1
            types = sorted({c.get("type", "?") for c in changes})
            report[host] = {"ok": False, "message": "temp changes still pending", "types": types}
            _safe_print("  ! %-30s pending: %s" % (host[:30], ", ".join(types)))
        else:
            report[host] = {"ok": True, "message": "clean", "types": []}
    if leftovers == 0:
        _safe_print("  \u2713 Post-revert verification: no temp changes remain on any device "
                    "(incl. on-target)")
    else:
        _safe_print("  ! %d device(s) in %s still carry temp changes -- see logs/errors.log"
                    % (leftovers, location_name))
    log_master("INFO", "post-revert verification for %s: %d leftover device(s)"
               % (location_name, leftovers))
    return report


# ===========================================================================
#  DEVICE PRE-CHECK, BACKUPS, HEALTH
# ===========================================================================
def pick_firmware(model: str) -> Tuple[str, str]:
    """Return (fw_file, target_version) for a model string, longest prefix first."""
    up = (model or "").upper()
    for prefix, fw, ver in MODEL_FIRMWARE_MAP:
        if up.startswith(prefix):
            return (fw, ver)
    return ("", TARGET_VERSION)


def verify_model_firmware_consistency(model: str, fw_file: str,
                                      target_ver: str) -> Tuple[bool, str]:
    """Cross-check a model against the image mapped to it.

    Catches the two mistakes that brick a maintenance window: a C9200 family
    chassis being handed the full cat9k image (or the reverse), and a filename
    that does not carry the target version.
    """
    if not model:
        return (False, "model unknown")
    if not fw_file:
        return (False, "no firmware mapped for '%s'" % model)
    tier, marker = model_family(model)
    if tier == "unknown":
        return (False, "model '%s' not in MODEL_FAMILY_MAP" % model)
    if marker:
        if marker not in fw_file:
            return (False, "model '%s' (lite family) needs '%s' in the filename"
                    % (model, marker))
    elif "_lite_" in fw_file:
        return (False, "model '%s' (full family) must not get the lite image" % model)
    if target_ver and target_ver not in fw_file:
        return (False, "target version %s not present in '%s'" % (target_ver, fw_file))
    return (True, "ok")


def preflight_firmware() -> Tuple[bool, List[str], List[str]]:
    """Validate the local firmware tree before a single device is touched.

    Returns ``(ok, errors, warnings)``.  A missing image or a family/name
    mismatch is fatal; an unusual file size is only a warning, because the
    exact byte count moves between maintenance releases and a stale bound must
    never block a fleet.
    """
    errors: List[str] = []
    warnings: List[str] = []
    seen = set()
    for prefix, fw_file, target_ver in MODEL_FIRMWARE_MAP:
        if fw_file in seen:
            continue
        seen.add(fw_file)
        path = FIRMWARE_DIR / fw_file
        if not path.exists():
            errors.append("missing firmware: %s" % path)
            continue
        try:
            size = path.stat().st_size
        except Exception as exc:
            errors.append("cannot stat %s: %s" % (path.name, exc))
            continue
        FIRMWARE_SIZES[fw_file] = size
        ok, reason = verify_model_firmware_consistency(prefix, fw_file, target_ver)
        if not ok:
            errors.append(reason)
        tier, _marker = model_family(prefix)
        low, high = FAMILY_SIZE_BOUNDS.get(tier, (0, 10 ** 12))
        megabytes = size / 1e6
        if not (low <= megabytes <= high):
            message = ("%s is %.0f MB, outside the expected %d-%d MB for the "
                       "%s family" % (fw_file, megabytes, low, high, tier))
            if FAMILY_SIZE_BOUNDS_STRICT:
                errors.append(message)
            else:
                warnings.append(message)
        FIRMWARE_SIZES.setdefault(fw_file, size)
    return (not errors, errors, warnings)


def model_family(model: str) -> Tuple[str, Optional[str]]:
    up = (model or "").upper()
    for prefix, value in MODEL_FAMILY_MAP.items():
        if up.startswith(prefix):
            return value
    return ("unknown", None)


def is_large_model(model: str) -> bool:
    up = (model or "").upper()
    return any(up.startswith(p) for p in LARGE_MODEL_PREFIXES)


def parse_model(show_version_out: str) -> str:
    out = show_version_out or ""
    for pattern in (r"[Mm]odel [Nn]umber\s*:\s*(\S+)",
                    r"[Mm]odel [Nn]umber\s*:\s*(\S+)",
                    r"^[Cc]isco (\S+).*[Pp]rocessor",
                    r"PID:\s*(\S+)"):
        m = re.search(pattern, out, re.M)
        if m:
            return m.group(1).strip().rstrip(",")
    return ""


def parse_free_bytes(dir_out: str) -> Optional[int]:
    out = dir_out or ""
    m = re.search(r"(\d[\d,]*)\s+bytes total\s*\((\d[\d,]*)\s+bytes free\)", out, re.I)
    if m:
        return int(m.group(2).replace(",", ""))
    m = re.search(r"(\d[\d,]*)\s+bytes (?:available|free)", out, re.I)
    if m:
        return int(m.group(1).replace(",", ""))
    m = re.search(r"free\s*[:\s]\s*(\d[\d,]*)", out, re.I)
    if m:
        return int(m.group(1).replace(",", ""))
    return None


def parse_dir_size(dir_out: str, name: str = "") -> Optional[int]:
    """Bytes of one entry in ``dir flash:`` output.

    Handles both ``idx  -rw-  <bytes>  Oct 10 2026 12:00:00  file.bin`` and the
    shorter ``<bytes>  Oct 10 2026 12:00:00  file.bin`` forms.
    """
    for line in (dir_out or "").splitlines():
        if name and name not in line:
            continue
        m = re.search(r"(\d[\d,]*)\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{4}", line)
        if m:
            return int(m.group(1).replace(",", ""))
        m = re.search(r"(\d[\d,]*)\s+bytes\b", line)
        if m and not name:
            return int(m.group(1).replace(",", ""))
    return None


def parse_stack_members(show_switch_out: str) -> int:
    count = 0
    for line in (show_switch_out or "").splitlines():
        if re.match(r"^\s*\*?\s*\d+\s+\S", line) and re.search(r"\b(Ready|Active|Standby|Member)\b",
                                                              line, re.I):
            count += 1
    return count


def _prompt_indicates_priv15(conn: Any) -> bool:
    """Fall back to the prompt character when 'show privilege' is blocked.

    Under TACACS+ command authorization the privilege query itself can be
    denied, yet the session may still be privileged; ``hostname#`` proves it.
    """
    try:
        prompt = conn.find_prompt() or ""
        return prompt.strip().endswith("#")
    except Exception:
        return False


def is_privileged(conn: Any, host: str = "") -> bool:
    """True when the session really has privilege 15."""
    if conn is None:
        return False
    try:
        out = _sh(conn, "show privilege", 30, host)
    except Exception:
        out = ""
    low = (out or "").lower()
    if any(marker in low for marker in _AUTHZ_FAIL_MARKERS):
        # Command was denied by the AAA server - trust the prompt instead.
        return _prompt_indicates_priv15(conn)
    m = re.search(r"privilege level is\s+(\d+)", low)
    if m:
        return int(m.group(1)) == 15
    m = re.search(r"level\s+(\d+)\b", low)
    if m:
        return int(m.group(1)) == 15
    if (out or "").strip():
        return False
    return _prompt_indicates_priv15(conn)


def classify_connect_error(exc: Any) -> str:
    """Map a transport failure onto the NON_RETRYABLE_PREFIXES vocabulary."""
    msg = str(exc or "").lower()
    if ("no acceptable kex" in msg or "incompatible ssh peer" in msg
            or "kex algorithm" in msg):
        return "SSH negotiation failed"
    if "no acceptable host key" in msg or "host key" in msg:
        return "SSH negotiation failed (host key)"
    if "no acceptable cipher" in msg or "no acceptable mac" in msg:
        return "SSH negotiation failed (crypto)"
    if ("authentication failed" in msg or "auth fail" in msg
            or "permission denied" in msg or "authentication exception" in msg):
        return "TACACS+ denied"
    return ""


def enable_user_prompt(conn: Any, host: str, pw: str) -> bool:
    """Interactive enable for TACACS+ boxes where netmiko's enable() stalls.

    Handles the two-step ``Username:`` / ``Password:`` form used when the AAA
    server wants a separate enable identity, and tolerates the case where the
    only reply is an authorization failure (the caller then falls back to the
    prompt character).
    """
    if conn is None or not pw:
        return False
    try:
        _drain_and_answer_prompts(conn, 2.0)
        conn.write_channel("enable\n")
        time.sleep(1.5)
        buf = _poll_read(conn) or ""
        if re.search(r"username\s*[:>]", buf, re.I) and ENABLE_USER:
            conn.write_channel(ENABLE_USER + "\n")
            time.sleep(1.0)
            buf += _poll_read(conn) or ""
        if re.search(r"password\s*[:>]", buf, re.I):
            conn.write_channel(pw + "\n")
            time.sleep(2.0)
            buf += _poll_read(conn) or ""
        low = buf.lower()
        if any(marker in low for marker in _AUTHZ_FAIL_MARKERS):
            dev_log(host, "WARN", "enable denied by AAA (TACACS+ command auth?)")
        return is_privileged(conn, host)
    except Exception as exc:
        if _is_dead_socket_error(str(exc)):
            return False
        return False


def ensure_priv15(conn: Any, host: str) -> bool:
    """Make sure the session is privileged, tolerating AAA oddities."""
    if conn is None:
        return False
    if is_privileged(conn, host):
        return True
    try:
        conn.enable()
    except Exception:
        pass
    if is_privileged(conn, host):
        return True
    pw = ENABLE_PASSWORD or getattr(conn, "secret", "") or ""
    if enable_user_prompt(conn, host, pw):
        dev_log(host, "OK", "privilege 15 established via interactive enable")
        return True
    dev_log(host, "ERROR", "not priv 15 on %s" % host)
    return False


def precheck_device(conn: Any, host: str, ip: str = "") -> Dict[str, Any]:
    """Read model, version, flash space and boot mode before touching anything."""
    info: Dict[str, Any] = {"ok": False, "error": "", "model": "", "version": "",
                            "fw_file": "", "target": TARGET_VERSION, "free_bytes": None,
                            "needed_bytes": 0, "members": 1, "boot_mode": "unknown",
                            "syntax": classify_install_syntax((0, 0, 0)), "clock_corrected": False}
    try:
        ver_out = _sh(conn, "show version", 120, host)
        if not (ver_out or "").strip():
            info["error"] = "unreachable: empty show version"
            return info
        info["version"] = parse_running_version(ver_out)
        info["model"] = parse_model(ver_out) or info.get("model", "")
        if not info["model"]:
            info["model"] = "UNKNOWN"
        fw, target = pick_firmware(info["model"])
        info["fw_file"] = fw
        info["target"] = target
        info["family"] = model_family(info["model"])[0]
        info["syntax"] = classify_install_syntax(_ver_tuple(info["version"]))
        if not fw:
            info["error"] = "unsupported model: %s (no firmware mapping)" % info["model"]
            return info

        if not ensure_priv15(conn, host):
            info["error"] = "not priv 15 on %s" % host
            return info

        switch_out = _sh(conn, "show switch", 60, host)
        info["members"] = max(1, parse_stack_members(switch_out))

        dir_out = _sh(conn, "dir flash:", 120, host)
        free = parse_free_bytes(dir_out)
        info["free_bytes"] = free
        fw_size = FIRMWARE_SIZES.get(fw, 0)
        # The image itself must fit, plus headroom for the unpacked packages
        # and one extra copy per additional stack member.
        base = (max(MIN_FREE_BYTES, fw_size + EXTRA_HEADROOM_BYTES) if fw_size
                else MIN_FREE_BYTES + EXTRA_HEADROOM_BYTES)
        need = base + STACK_MEMBER_HEADROOM * (info["members"] - 1)
        info["fw_size"] = fw_size
        info["needed_bytes"] = need
        if free is not None and free < need:
            info["error"] = ("insufficient_space: %d free, %d needed on %s"
                             % (free, need, host))
            return info
        if free is None:
            dev_log(host, "WARN", "could not read flash free space; continuing")

        boot_out = _sh(conn, "show boot | include BOOT", 60, host)
        boot_line = ""
        for line in (boot_out or "").splitlines():
            if "BOOT" in line.upper() and "variable" in line.lower():
                boot_line = line.strip()
                break
        if not boot_line:
            boot_line = (boot_out or "").strip().splitlines()[-1] if (boot_out or "").strip() else ""
        if "packages.conf" in boot_line:
            info["boot_mode"] = "install"
        elif ".bin" in boot_line:
            info["boot_mode"] = "bundle"
        else:
            info["boot_mode"] = "unknown"
        if info["boot_mode"] == "bundle":
            if not ALLOW_BUNDLE_MODE_CONVERSION:
                info["error"] = ("not_install_mode: bundle boot and conversion "
                                 "is disabled (--no-bundle-mode)")
                return info
            ok, msg = ensure_install_mode(conn, host)
            if not ok:
                info["error"] = "not_install_mode: %s" % msg
                return info
            info["boot_mode"] = "install"

        info["ok"] = True
        return info
    except Exception as exc:
        info["error"] = _one_line("%s: %s" % (type(exc).__name__, exc))
        return info


def ensure_install_mode(conn: Any, host: str) -> Tuple[bool, str]:
    """Convert a bundle-boot device to install mode (we never upgrade bundles)."""
    dir_out = _sh(conn, "dir flash: | include packages.conf", 60, host)
    if "packages.conf" not in (dir_out or ""):
        return (False, "packages.conf missing on flash")
    _send_long(conn, "configure terminal", 30, host, answer_confirm=False)
    _send_long(conn, "no boot system", 30, host, answer_confirm=False)
    _send_long(conn, "boot system flash:packages.conf", 30, host, answer_confirm=False)
    _send_long(conn, "end", 30, host, answer_confirm=False)
    dev_log(host, "OK", "boot variable switched to packages.conf (install mode)")
    return (True, "install mode enabled")


def _one_line(text: Any, limit: int = 200) -> str:
    """Collapse a multi-line exception (netmiko loves those) into one line."""
    flat = re.sub(r"\s+", " ", str(text or "")).strip()
    return flat[:limit]


def peek_device(ip: str, host: str, user: str, pw: str,
                enable_pw: str = "") -> Dict[str, Any]:
    """Cheap read-only sweep used by --check and the model pre-scan.

    A TCP/22 probe runs first: on a 500 device fleet, waiting out a 30 s SSH
    timeout for every powered-off switch dominates the run time.
    """
    conn = None
    result = {"hostname": host, "ip": ip, "model": "", "version": "", "error": ""}
    if not ssh_reachable(ip):
        result["error"] = "unreachable on tcp/22"
        return result
    try:
        conn = do_connect(ip, host, user, pw, enable_pw, fast=True)
        if not ensure_priv15(conn, host):
            result["error"] = "not priv 15"
            ver_out = _sh(conn, "show version", 120, host)
            result["version"] = parse_running_version(ver_out)
            result["model"] = parse_model(ver_out)
            return result
        ver_out = _sh(conn, "show version", 120, host)
        result["version"] = parse_running_version(ver_out)
        result["model"] = parse_model(ver_out)
        if not result["version"]:
            result["error"] = "could not parse version"
    except Exception as exc:
        result["error"] = classify_connect_error(exc) or \
            _one_line("%s: %s" % (type(exc).__name__, exc))
    finally:
        _disconnect(conn)
    return result


def backup_config(conn: Any, host: str) -> str:
    """Snapshot the running config into backups\\<host>_<RUN_ID>_pre.cfg."""
    text = _sh(conn, "show running-config", 180, host)
    if text:
        path = BACKUP_DIR / ("%s_%s_pre.cfg" % (host, RUN_ID))
        try:
            _ensure_dir(BACKUP_DIR)
            with open(path, "w", encoding="utf-8", errors="replace") as fh:
                fh.write(text)
            dev_log(host, "OK", "running-config backed up to %s" % path.name)
        except Exception as exc:
            dev_log(host, "WARN", "backup failed: %s" % exc)
    return text


def _normalize_config(text: str) -> List[str]:
    """Bug B14: drop the exact line ``end`` only.

    Dropping every line that merely starts with "end" would destroy
    ``endpoint-*`` / ``end-user-*`` style configuration lines.
    """
    out: List[str] = []
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped == "end":
            continue
        if not stripped:
            continue
        out.append(stripped)
    return out


def _is_drift_noise(line: str) -> bool:
    """True for lines the orchestrator itself adds or removes.

    The service locks and the SSH/crypto tuning are restored later, so seeing
    them in a config diff is expected and must never be reported as drift.
    """
    body = line.lstrip("+-").strip()
    return any(body.startswith(prefix) for prefix in DRIFT_NOISE_PREFIXES)


def config_diff(pre: str, post: str) -> List[str]:
    """Normalized config diff with the orchestrator's own changes filtered out."""
    if not pre or not post:
        return []
    pre_set = set(_normalize_config(pre))
    post_set = set(_normalize_config(post))
    changed = sorted((pre_set - post_set) | (post_set - pre_set))
    return [line for line in changed if not _is_drift_noise(line)]


def config_diff_lines(pre: str, post: str) -> int:
    return len(config_diff(pre, post))


def health_check(conn: Any, host: str, expected_members: int = 1) -> Tuple[bool, str]:
    intf = _sh(conn, "show ip interface brief", 90, host)
    up = len(re.findall(r"\bup\s+up\b", intf or "", re.I))
    sw = _sh(conn, "show switch", 60, host)
    members = parse_stack_members(sw) if sw else expected_members
    version = parse_running_version(_sh(conn, "show version | include Version", 60, host))
    ok = up > 0 and members >= max(1, expected_members)
    detail = "interfaces_up=%d stack_members=%d version=%s" % (up, members, version or "?")
    return ok, detail


# ===========================================================================
#  SCP / SFTP TRANSFER
# ===========================================================================
def _pscp_pwfile() -> str:
    return "%s%d_%d.tmp" % (_PWFILE_BASE, os.getpid(), threading.get_ident())


def _write_pwfile(path: str, pw: str) -> bool:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(pw)
        return True
    except Exception:
        return False


def _kill_proc(proc: Any) -> None:
    """terminate(), then kill() as the fallback (see ROBUSTNESS)."""
    try:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
        if proc.poll() is None:
            try:
                proc.kill()
            except Exception:
                pass
    except Exception:
        pass


def _parse_pscp_pct(text: str) -> Optional[float]:
    m = re.search(r"(\d{1,3})\s*%", text or "")
    if m:
        try:
            return float(m.group(1))
        except Exception:
            return None
    return None


def _remote_file_size(ip: str, user: str, pw: str, remote_name: str, host: str = "") -> Optional[int]:
    """Probe the size of the partially transferred file on the switch.

    Two attempts per probe; the caller runs this on its own connection so the
    pscp pipe is never disturbed.
    """
    if ConnectHandler is None:
        return None
    if not SESSION_SEM.acquire(timeout=1):
        return None
    try:
        for _attempt in range(2):
            conn = None
            try:
                conn = do_connect(ip, host, user, pw, fast=True)
                out = _sh(conn, "dir flash:%s" % remote_name, 60, host)
                size = parse_dir_size(out, remote_name) if out else None
                if size:
                    return size
            except Exception:
                time.sleep(2)
            finally:
                _disconnect(conn)
        return None
    finally:
        try:
            SESSION_SEM.release()
        except Exception:
            pass
    return None


def _pscp_run_once(ip: str, user: str, pw: str, local_path: str, remote_name: str,
                   host: str = "") -> Dict[str, Any]:
    """One pscp attempt.

    Bug B1: ``select.select()`` on a Windows pipe raises OSError(10038), so the
    old code silently blocked in read() and the stall watchdog never fired.
    A reader thread now drains proc.stdout into a bounded queue and the main
    loop uses ``q.get(timeout=3.0)``.
    """
    result: Dict[str, Any] = {"ok": False, "error": "", "bytes": 0,
                              "seconds": 0.0, "stalled": False, "output": []}
    exe = str(PSCP_EXE)
    if not os.path.exists(exe):
        result["error"] = "pscp.exe not found at %s" % exe
        return result
    if not os.path.exists(local_path):
        result["error"] = "firmware not found: %s" % local_path
        return result

    pwfile = _pscp_pwfile()
    use_pwfile = _write_pwfile(pwfile, pw)
    started = time.time()
    try:
        base = [exe, "-batch"]
        if use_pwfile:
            base += ["-pwfile", pwfile]
        else:
            base += ["-pw", pw]
        cmd = base + ["-scp", "-unsafe", local_path, "%s@%s:flash:/%s" % (user, ip, remote_name)]
        dev_log(host, "CMD", "pscp -> %s:flash:/%s" % (ip, remote_name))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, bufsize=0)

        q: "queue.Queue[bytes]" = queue.Queue(maxsize=1024)

        def _reader() -> None:
            try:
                for chunk in iter(proc.stdout.readline, b""):
                    try:
                        q.put(chunk, timeout=1.0)
                    except queue.Full:
                        pass
            except Exception:
                pass
            finally:
                try:
                    proc.stdout.close()
                except Exception:
                    pass

        reader = threading.Thread(target=_reader, name="pscp-reader-%s" % (host or ip), daemon=True)
        reader.start()

        last_data = time.time()
        last_probe = time.time()
        last_size = 0
        no_growth = 0
        stdin_closed = False
        while True:
            if SHUTDOWN_REQ.is_set():
                _kill_proc(proc)
                result["error"] = "shutdown requested"
                result["stalled"] = True
                break
            line = None
            try:
                line = q.get(timeout=3.0)
            except queue.Empty:
                line = None
            if line is not None:
                text = line.decode("utf-8", "replace").rstrip("\r\n")
                if text:
                    result["output"].append(text)
                    if len(result["output"]) > 400:
                        del result["output"][:200]
                    last_data = time.time()
                    if host:
                        dev_live_log(host, text)
                    if not stdin_closed:
                        pct = _parse_pscp_pct(text)
                        if pct is not None:
                            set_phase(host, "TRANSFER", _progress_bar(pct), pct=pct)
                        elif "password" in text.lower() or "are you sure" in text.lower():
                            try:
                                proc.stdin.write(b"y\n")
                                if hasattr(proc.stdin, "flush"):
                                    proc.stdin.flush()
                            except Exception:
                                pass
            if proc.poll() is not None and q.empty() and not reader.is_alive():
                break
            now = time.time()
            if line is None and (now - last_data) > SCP_STALL_TIMEOUT:
                dev_log(host, "ERROR", "pscp produced no output for %ds; killing transfer"
                        % SCP_STALL_TIMEOUT)
                _kill_proc(proc)
                result["error"] = "transfer stalled (>%ds without output)" % SCP_STALL_TIMEOUT
                result["stalled"] = True
                break
            if line is None and (now - last_probe) > SCP_SIZE_CHECK_INTERVAL:
                last_probe = now
                size = _remote_file_size(ip, user, pw, remote_name, host)
                if size is not None:
                    if size > last_size:
                        last_size = size
                        no_growth = 0
                        last_data = now  # remote side is making progress
                    else:
                        no_growth += 1
                        if no_growth >= 3:
                            dev_log(host, "ERROR", "remote file size static at %d for %d probes"
                                    % (size, no_growth))
                            _kill_proc(proc)
                            result["error"] = "transfer stalled (remote size static)"
                            result["stalled"] = True
                            break

        rc = proc.poll()
        if rc is None:
            try:
                rc = proc.wait(timeout=20)
            except Exception:
                _kill_proc(proc)
                rc = -1
        result["seconds"] = round(time.time() - started, 1)
        result["bytes"] = last_size or (os.path.getsize(local_path) if os.path.exists(local_path) else 0)
        if result["error"]:
            result["ok"] = False
        elif rc == 0:
            result["ok"] = True
        else:
            tail = "\n".join(result["output"][-6:])
            result["error"] = "pscp exited %s: %s" % (rc, tail.strip()[-400:])
            if "-pwfile" in cmd and re.search(r"(unknown option|illegal option|-pwfile)", tail, re.I):
                result["retry_with_pw"] = True
        return result
    except Exception as exc:
        result["error"] = _one_line("%s: %s" % (type(exc).__name__, exc))
        return result
    finally:
        try:
            if os.path.exists(pwfile):
                os.remove(pwfile)
        except Exception:
            pass


def _sftp_transfer(ip: str, user: str, pw: str, local_path: str, remote_name: str,
                   host: str = "") -> Dict[str, Any]:
    """paramiko SFTP fallback when pscp is unusable."""
    out: Dict[str, Any] = {"ok": False, "error": "", "bytes": 0, "seconds": 0.0,
                           "stalled": False, "output": []}
    if paramiko is None:
        out["error"] = "paramiko not installed for SFTP fallback"
        return out
    started = time.time()
    client = None
    sftp = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=user, password=pw, timeout=CONNECT_TIMEOUT_SEC,
                       banner_timeout=CONNECT_TIMEOUT_SEC, auth_timeout=CONNECT_TIMEOUT_SEC,
                       look_for_keys=False, allow_agent=False)
        transport = client.get_transport()
        if transport is not None:
            transport.set_keepalive(30)
        sftp = client.open_sftp()
        total = os.path.getsize(local_path)
        remote = "flash:/%s" % remote_name
        sent = {"n": 0}

        def _cb(done: int, _total: int) -> None:
            sent["n"] = done
            pct = (done / total * 100.0) if total else 0.0
            set_phase(host, "TRANSFER", _progress_bar(pct), pct=pct)

        sftp.put(local_path, remote, callback=_cb)
        out["ok"] = True
        out["bytes"] = sent["n"] or total
        out["seconds"] = round(time.time() - started, 1)
        return out
    except Exception as exc:
        out["error"] = "sftp fallback failed: %s: %s" % (type(exc).__name__, exc)
        return out
    finally:
        for obj in (sftp, client):
            try:
                if obj is not None:
                    obj.close()
            except Exception:
                pass


def transfer_firmware(dev: Any, user: str, pw: str, fw_file: str) -> Dict[str, Any]:
    """pscp with retries, with an SFTP fallback when pscp cannot be used."""
    host = dev.hostname
    local_path = str(FIRMWARE_DIR / fw_file)
    if not os.path.exists(local_path):
        return {"ok": False, "error": "firmware missing locally: %s" % local_path}
    local_size = os.path.getsize(local_path)
    last: Dict[str, Any] = {"ok": False, "error": "no attempt made"}
    for attempt in range(1, max(1, TRANSFER_RETRY_ATTEMPTS) + 1):
        if SHUTDOWN_REQ.is_set():
            return {"ok": False, "error": "shutdown requested"}
        set_phase(host, "TRANSFER", "attempt %d/%d" % (attempt, TRANSFER_RETRY_ATTEMPTS))
        if USE_PSCP:
            last = _pscp_run_once(dev.ip, user, pw, local_path, fw_file, host)
            if last.get("retry_with_pw"):
                last = _pscp_run_once(dev.ip, user, pw, local_path, fw_file, host)
        if not last.get("ok") and PSCP_TRANSFER_FALLBACK:
            dev_log(host, "WARN", "pscp failed (%s); trying SFTP fallback" % last.get("error"))
            fallback = _sftp_transfer(dev.ip, user, pw, local_path, fw_file, host)
            if fallback.get("ok"):
                last = fallback
        if last.get("ok"):
            remote_size = _remote_file_size(dev.ip, user, pw, fw_file, host)
            if remote_size is not None and abs(remote_size - local_size) > 4096:
                last = {"ok": False, "error": "size mismatch: local=%d remote=%d"
                        % (local_size, remote_size)}
            else:
                last["local_size"] = local_size
                dev_log(host, "OK", "transfer complete in %.1fs" % last.get("seconds", 0.0))
                return last
        dev_log(host, "WARN", "transfer attempt %d/%d failed: %s"
                % (attempt, TRANSFER_RETRY_ATTEMPTS, last.get("error")))
        if attempt < TRANSFER_RETRY_ATTEMPTS:
            SHUTDOWN_REQ.wait(TRANSFER_RETRY_DELAY_SEC)
    return last


def local_md5(path: str, chunk: int = 1024 * 1024) -> str:
    digest = hashlib.md5()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _extract_md5(text: str) -> str:
    m = re.search(r"=\s*([0-9a-fA-F]{32})\b", text or "")
    if m:
        return m.group(1).lower()
    m = re.search(r"\b([0-9a-fA-F]{32})\b", text or "")
    return m.group(1).lower() if m else ""


def verify_firmware_md5(conn: Any, host: str, fw_file: str, local_path: str) -> Tuple[bool, str]:
    """Hash verified transfer (VERIFY_TRANSFER_HASH); size check as the fallback."""
    local_size = os.path.getsize(local_path) if os.path.exists(local_path) else 0
    dir_out = _sh(conn, "dir flash:%s" % fw_file, 60, host)
    remote_size = parse_dir_size(dir_out, fw_file)
    if remote_size is None:
        return (False, "size mismatch: cannot read flash entry for %s" % fw_file)
    if abs(remote_size - local_size) > 4096:
        return (False, "size mismatch: local=%d remote=%d" % (local_size, remote_size))
    if not VERIFY_TRANSFER_HASH:
        return (True, "size ok (%d bytes)" % remote_size)
    out, why = _send_long(conn, "verify /md5 flash:%s" % fw_file, MD5_DEADLINE_SEC, host)
    if why in ("dead", "shutdown"):
        return (False, "session lost during md5 verification")
    remote_md5 = _extract_md5(out)
    if not remote_md5:
        dev_log(host, "WARN", "could not parse remote md5; accepting size match")
        return (True, "size ok (%d bytes), md5 unparsed" % remote_size)
    want = local_md5(local_path)
    if remote_md5 != want:
        return (False, "MD5 mismatch: local=%s remote=%s" % (want, remote_md5))
    return (True, "md5 verified (%s)" % want)


# ===========================================================================
#  STATE CLASSIFIER  (design rule P1 -- exact rules from the specification)
# ===========================================================================
def _file_on_flash(conn: Any, host: str, fw_file: str) -> bool:
    if not fw_file:
        return False
    out = _sh(conn, "dir flash: | include %s" % fw_file, 90, host)
    if out and fw_file in out:
        return True
    if not out:
        full = _sh(conn, "dir flash:", 120, host)
        return fw_file in (full or "")
    return False


def classify_state(conn: Any, host: str, ip: str, target_ver: str, fw_file: str,
                   st: Optional[Dict[str, Any]] = None,
                   skip_log_check: bool = False) -> Tuple[str, Dict[str, Any]]:
    """Read state (in order), then return exactly one classification."""
    st = st if st is not None else {}
    info: Dict[str, Any] = {"version": "", "target_status": None, "summary": {},
                            "file_on_flash": False, "reason": ""}
    if conn is None or not _session_is_alive(conn):
        info["reason"] = "session dead"
        return ("UNREACHABLE", info)

    ver_out = _sh(conn, "show version | include Version", 90, host)
    if not (ver_out or "").strip():
        if not _session_is_alive(conn):
            info["reason"] = "session died on show version"
            return ("UNREACHABLE", info)
        info["reason"] = "show version returned nothing"
        return ("UNKNOWN", info)
    running_ver = parse_running_version(ver_out)
    if not running_ver:
        info["reason"] = "unparseable version output"
        return ("UNKNOWN", info)
    info["version"] = running_ver
    running_target = (_ver_tuple(running_ver) == _ver_tuple(target_ver))

    boot_out = _sh(conn, "show boot | include BOOT", 60, host)
    info["boot"] = (boot_out or "").strip()[-160:]

    summary_out = _sh(conn, "show install summary", 120, host)
    if not (summary_out or "").strip():
        info["reason"] = "show install summary returned nothing"
        return ("UNKNOWN", info)
    summary = _parse_install_summary(summary_out)
    info["summary"] = summary
    info["summary_raw"] = _trim1200(summary_out)
    target_status = _sum_status_for(summary, target_ver)
    info["target_status"] = target_status

    file_on_flash = _file_on_flash(conn, host, fw_file)
    info["file_on_flash"] = file_on_flash

    if running_target and summary_committed_on_target(summary, target_ver):
        info["reason"] = "version and summary both on target"
        return ("DONE_COMMITTED", info)

    if running_target and target_status in ("A", "U"):
        info["reason"] = "running target, summary %s" % target_status
        return ("RUNNING_UNCOMMITTED", info)

    if running_target and target_status is None:
        info["reason"] = "running target, summary parser miss"
        return ("RUNNING_UNKNOWN", info)

    if target_status == "I":
        info["reason"] = "target present but inactive"
        return ("ACTIVATABLE_INACTIVE", info)

    if target_status in ("A", "U") and not running_target:
        info["reason"] = "summary %s, running %s" % (target_status, running_ver)
        return ("ACTIVATED_NEEDS_RELOAD", info)

    if target_status == "C" and not running_target:
        info["reason"] = "summary committed, running %s" % running_ver
        return ("COMMITTED_NEEDS_RELOAD", info)

    # BROKEN fires only here: no DB entry, not running the target, file present
    # on flash and the install log shows an engine exit(N).
    if (target_status is None and not running_target and file_on_flash
            and not skip_log_check and not st.get("escalated")):
        log_out = _sh(conn, "show install log | include exit", 120, host)
        info["install_log"] = _trim1200(log_out)
        if "exit(" in (log_out or ""):
            info["reason"] = "install log reports a failed engine run"
            return ("BROKEN", info)

    if file_on_flash and target_status is None:
        info["reason"] = "file on flash, no install DB entry"
        return ("NEEDS_ADD", info)

    if not file_on_flash:
        info["reason"] = "firmware not on flash"
        return ("NEEDS_TRANSFER", info)

    info["reason"] = "no rule matched"
    return ("UNKNOWN", info)


def _finalize_install_commit(conn: Any, host: str, target_ver: str,
                             fw_file: str) -> Tuple[bool, str]:
    """Confirm the target is committed.

    The strict ``show install summary`` check comes first.  When it cannot
    confirm, the commit command is issued (this is the RUNNING_UNCOMMITTED
    action), and only then do the parser-independent signals get consulted:
    ``show install active summary`` and ``show boot`` = packages.conf together
    with ``show version`` = target.
    """
    out = _sh(conn, "show install summary", 120, host)
    summary = _parse_install_summary(out)
    if summary_committed_on_target(summary, target_ver):
        return (True, "summary shows %s committed" % target_ver)

    _out, why = _send_long(conn, "install commit", COMMIT_DEADLINE_SEC, host)
    if why in ("dead", "shutdown"):
        return (False, "session lost during install commit")

    confirm = _sh(conn, "show install summary", 120, host)
    confirm_summary = _parse_install_summary(confirm)
    if summary_committed_on_target(confirm_summary, target_ver):
        return (True, "install commit accepted")
    if _sum_status_for(confirm_summary, target_ver) == "C":
        return (True, "install commit accepted (summary)")

    active = _sh(conn, "show install active summary", 120, host)
    active_summary = _parse_install_summary(active)
    if _sum_status_for(active_summary, target_ver) == "C" or \
            summary_committed_on_target(active_summary, target_ver):
        return (True, "active summary shows %s committed" % target_ver)

    boot_out = _sh(conn, "show boot | include BOOT", 60, host)
    ver_out = _sh(conn, "show version | include Version", 60, host)
    running = parse_running_version(ver_out)
    if (why == "done" and "packages.conf" in (boot_out or "")
            and _ver_tuple(running) == _ver_tuple(target_ver)):
        return (True, "commit accepted (boot=packages.conf, version=%s)" % running)
    return (False, "commit not confirmed (%s)" % why)


# ===========================================================================
#  STATE MACHINE  (one read, one classify, one command, loop)
# ===========================================================================
def run_state_machine(conn: Any, host: str, ip: str, user: str, pw: str,
                      target_ver: str, fw_file: str, syntax: Dict[str, Any],
                      st: Dict[str, Any]) -> Tuple[bool, str, Any]:
    """Drive one device to DONE_COMMITTED.

    Returns ``(ok, error, conn)``.  ``conn`` is None when a reload was issued
    and the caller must wait for the device and reconnect.
    """
    deadline = time.time() + STATE_MACHINE_DEADLINE
    while True:
        if SHUTDOWN_REQ.is_set():
            return (False, "shutdown requested", conn)
        # Bug B3: the escalation cap is checked at the TOP of the loop, before
        # the classification, so a device wedged on ACTIVATABLE_INACTIVE cannot
        # spin until STATE_MAX_SAME.
        if st.get("escalations", 0) > MAX_ESCALATIONS:
            return (False, "max escalations (%d) exceeded" % st.get("escalations", 0), conn)
        if time.time() > deadline:
            return (False, "state machine deadline (%ds) exceeded" % STATE_MACHINE_DEADLINE, conn)

        state, info = classify_state(conn, host, ip, target_ver, fw_file, st,
                                     skip_log_check=bool(st.get("escalated")))
        if state == st.get("last_state"):
            st["same"] = st.get("same", 0) + 1
        else:
            st["same"] = 0
            st["last_state"] = state
        if st["same"] >= STATE_MAX_SAME:
            st["escalations"] = st.get("escalations", 0) + 1
            st["same"] = 0
            dev_log(host, "WARN", "state %s repeated %d times -> escalation %d"
                    % (state, STATE_MAX_SAME, st["escalations"]))
            if st["escalations"] > MAX_ESCALATIONS:
                return (False, "stuck in %s for %d polls" % (state, STATE_MAX_SAME), conn)

        set_phase(host, "INSTALL", state)
        dev_log(host, "STEP", "state=%s version=%s summary=%s file=%s (%s)"
                % (state, info.get("version"), info.get("summary"),
                   info.get("file_on_flash"), info.get("reason")))

        if state == "DONE_COMMITTED":
            return (True, "", conn)

        if state == "RUNNING_UNCOMMITTED":
            ok, msg = _finalize_install_commit(conn, host, target_ver, fw_file)
            st["attempts"] = st.get("attempts", 0) + 1
            if ok:
                dev_log(host, "OK", msg)
                return (True, "", conn)
            dev_log(host, "WARN", "commit finalisation: %s" % msg)

        elif state == "RUNNING_UNKNOWN":
            st["commit_tries"] = st.get("commit_tries", 0) + 1
            _out, why = _send_long(conn, "install commit", COMMIT_DEADLINE_SEC, host)
            if why == "dead":
                conn = _fresh_conn(conn, host, ip, user, pw)
                if conn is None:
                    return (False, "unreachable during commit", None)
            if st["commit_tries"] >= 3:
                dev_log(host, "WARN", "accepting device after 3 unparsed commit attempts")
                return (True, "", conn)

        elif state == "ACTIVATABLE_INACTIVE":
            accepted = False
            forms = build_activate_cmds(fw_file, syntax)
            for idx, cmd in enumerate(forms):
                out, why = _send_long(conn, cmd, ACTIVATE_DEADLINE_SEC, host)
                if why in ("dead", "shutdown"):
                    conn = _fresh_conn(conn, host, ip, user, pw)
                    if conn is None:
                        return (False, "unreachable during activate", None)
                    break
                if why == "fastfail" and _ACTIVATE_REJECT_RE.search(out or ""):
                    dev_log(host, "WARN", "activate form rejected: %s" % cmd)
                    if idx + 1 < len(forms):
                        continue
                    st["escalations"] = st.get("escalations", 0) + 1
                else:
                    accepted = True
                break
            if not accepted:
                st["attempts"] = st.get("attempts", 0) + 1

        elif state in ("ACTIVATED_NEEDS_RELOAD", "COMMITTED_NEEDS_RELOAD"):
            st["reloads"] = st.get("reloads", 0) + 1
            if st["reloads"] > 1:
                return (False, "reload loop detected (%s after reload)" % state, conn)
            _issue_reload(conn, host)
            _disconnect(conn)
            return (True, "", None)

        elif state == "BROKEN":
            _send_long(conn, "install abort", 300, host)
            _send_long(conn, "install remove inactive", 900, host)
            st["escalated"] = True
            st["escalations"] = st.get("escalations", 0) + 1
            dev_log(host, "WARN", "install DB cleared (BROKEN) -> escalation %d"
                    % st["escalations"])

        elif state == "NEEDS_ADD":
            out, why = _send_long(conn, "install add file flash:%s" % fw_file,
                                  INSTALL_ADD_DEADLINE_SEC, host)
            if why == "dead":
                conn = _fresh_conn(conn, host, ip, user, pw)
                if conn is None:
                    return (False, "unreachable during install add", None)
            elif why == "fastfail":
                st["escalations"] = st.get("escalations", 0) + 1
                dev_log(host, "ERROR", "install add failed: %s" % (out or "")[-300:])
            st["attempts"] = st.get("attempts", 0) + 1

        elif state == "NEEDS_TRANSFER":
            return (False, "needs_transfer", conn)

        elif state == "UNREACHABLE":
            conn = _fresh_conn(conn, host, ip, user, pw)
            if conn is None:
                return (False, "unreachable", None)

        elif state == "UNKNOWN":
            pass

        SHUTDOWN_REQ.wait(STATE_POLL_INTERVAL)


# ===========================================================================
#  POST RELOAD WORK
# ===========================================================================
def wait_reboot_and_verify(ip: str, target_ver: str, host: str, user: str, pw: str,
                           st: Dict[str, Any], pre_config: str, fw_file: str,
                           syntax: Dict[str, Any]) -> Tuple[bool, str, Any]:
    """Ping down -> ping up -> SSH up -> settle -> finalise -> health check."""
    set_phase(host, "REBOOT", "waiting for link down")
    _wait_ping(ip, expect_up=False, timeout=PING_DOWN_TIMEOUT_SEC, poll=PING_DOWN_POLL_SEC, host=host)
    set_phase(host, "REBOOT", "waiting for link up")
    if not _wait_ping(ip, expect_up=True, timeout=PING_UP_TIMEOUT_SEC, poll=PING_UP_POLL_SEC, host=host):
        return (False, "device did not come back (ping timeout)", None)

    set_phase(host, "REBOOT", "waiting for ssh")
    conn = None
    deadline = time.time() + POST_REBOOT_SSH_WAIT_SEC
    attempts = 0
    while attempts < POST_REBOOT_MAX_ATTEMPTS and time.time() < deadline:
        if SHUTDOWN_REQ.is_set():
            return (False, "shutdown requested", None)
        attempts += 1
        if not ssh_port_open(ip, timeout=3):
            # Port still closed: the box is mid-boot.  Probing first avoids
            # burning auth attempts (and TACACS+ lockout counters) on a switch
            # whose SSH daemon has not started yet.
            SHUTDOWN_REQ.wait(POST_REBOOT_DELAY_SEC)
            continue
        try:
            conn = do_connect(ip, host, user, pw, pw)
        except Exception as exc:
            dev_log(host, "INFO", "post-reboot ssh attempt %d: %s"
                    % (attempts, classify_connect_error(exc) or
                       _one_line(exc, 120)))
            conn = None
        if conn is not None:
            break
        SHUTDOWN_REQ.wait(POST_REBOOT_DELAY_SEC)
    if conn is None:
        return (False, "ssh did not return after reload", None)

    set_phase(host, "VERIFY", "settling")
    # Bug B8: shutdown aware wait keeps Ctrl+C responsive during the settle.
    SHUTDOWN_REQ.wait(POST_REBOOT_SETTLE_SEC)
    if SHUTDOWN_REQ.is_set():
        return (False, "shutdown requested", conn)

    set_phase(host, "VERIFY", "finalising install")
    ok, err, conn = run_state_machine(conn, host, ip, user, pw, target_ver, fw_file, syntax, st)

    set_phase(host, "VERIFY", "version check")
    ver_out = _sh(conn, "show version | include Version", 90, host)
    post_ver = parse_running_version(ver_out)
    st["post_version"] = post_ver
    if _ver_tuple(post_ver) != _ver_tuple(target_ver):
        return (False, "post-reboot version %s != %s" % (post_ver or "?", target_ver), conn)

    health_ok, health_msg = health_check(conn, host, st.get("members", 1))
    dev_log(host, "OK" if health_ok else "WARN", "post-reboot health: %s" % health_msg)

    if pre_config and not SKIP_CONFIG_DRIFT_CHECK:
        post_config = _sh(conn, "show running-config", 180, host)
        drift = config_diff(pre_config, post_config)
        st["config_diff_lines"] = len(drift)
        if drift:
            dev_log(host, "WARN", "config drift: %d unexpected line(s): %s"
                    % (len(drift), "; ".join(drift[:5])))

    if not health_ok:
        return (False, "post-reboot health check failed: %s" % health_msg, conn)
    return (ok, err, conn)


# ===========================================================================
#  DEVICE MODEL AND RUN BOOKKEEPING
# ===========================================================================
@dataclass
class Device:
    hostname: str
    ip: str
    location: str = ""
    model: str = ""
    model_hint: str = ""
    start_version: str = ""
    fw_file: str = ""
    target: str = TARGET_VERSION

    def to_row(self) -> Dict[str, Any]:
        return {"hostname": self.hostname, "ip": self.ip, "model": self.model or self.model_hint,
                "start_version": self.start_version, "target_version": self.target,
                "fw_file": self.fw_file, "location": self.location}


@dataclass
class RunCtx:
    user: str = ""
    pw: str = ""
    enable_pw: str = ""
    location: str = ""
    run_id: str = RUN_ID


RUN_RECORDS: Dict[str, Dict[str, Any]] = {}
RUN_RECORDS_LOCK = threading.RLock()
_CKPT_LOCK = threading.RLock()
_CKPT_SEEN: Dict[str, str] = {}

RECORD_FIELDS = ["hostname", "ip", "status", "stage", "start_version", "target_version",
                 "post_version", "fw_file", "md5_ok", "install_started", "reboot_detected",
                 "verify_pending", "clock_corrected", "config_diff_lines", "duration_sec",
                 "attempts", "error"]


def new_record(dev: Device, location: str) -> Dict[str, Any]:
    rec = {k: "" for k in RECORD_FIELDS}
    rec.update({"hostname": dev.hostname, "ip": dev.ip, "location": location,
                "status": "PENDING", "stage": "QUEUE", "target_version": dev.target or TARGET_VERSION,
                "md5_ok": "", "install_started": False, "reboot_detected": False,
                "verify_pending": True, "clock_corrected": False, "config_diff_lines": 0,
                "duration_sec": 0.0, "attempts": 0, "error": ""})
    with RUN_RECORDS_LOCK:
        RUN_RECORDS[dev.hostname] = rec
    return rec


def update_record(host: str, **fields: Any) -> None:
    with RUN_RECORDS_LOCK:
        rec = RUN_RECORDS.get(host)
        if rec is None:
            return
        for key, value in fields.items():
            if key in rec:
                rec[key] = value
        location = rec.get("location") or ""
        stage = rec.get("stage") or ""
    if location and stage and stage != _CKPT_SEEN.get(host):
        _CKPT_SEEN[host] = stage
        touch_device_checkpoint(location, host, stage, rec.get("error", "") or "")


def snapshot_records() -> List[Dict[str, Any]]:
    with RUN_RECORDS_LOCK:
        return [dict(rec) for rec in RUN_RECORDS.values()]


def retryable_failure(host: str) -> bool:
    """True when a failed device is worth another attempt.

    Only transfer-phase failures qualify: once ``install add`` has started, a
    retry risks fighting a half-finished install engine run, which is exactly
    what NON_RETRYABLE_PREFIXES guards against.
    """
    with RUN_RECORDS_LOCK:
        rec = RUN_RECORDS.get(host)
        if not rec:
            return False
        record = dict(rec)
    if record.get("status") != "FAILED":
        return False
    if record.get("install_started"):
        return False
    if (record.get("stage") or "").upper() not in ("QUEUE", "PRE-CHECK", "SERVICE-LOCKS",
                                                   "TRANSFER", "RETRY"):
        return False
    error = (record.get("error") or "").strip()
    if not error:
        return False
    lowered = error.lower()
    return not any(lowered.startswith(prefix.lower()) for prefix in NON_RETRYABLE_PREFIXES)


class large_guard:
    """Throttle the number of C9300/C9500 transfers running at once."""

    def __init__(self, needed: bool) -> None:
        self.needed = bool(needed)
        self.held = False

    def __enter__(self) -> "large_guard":
        if self.needed:
            self.held = LARGE_SEM.acquire(timeout=3600)
        return self

    def __exit__(self, *exc: Any) -> None:
        if self.needed and self.held:
            try:
                LARGE_SEM.release()
            except Exception:
                pass


# ===========================================================================
#  WORKERS
# ===========================================================================
def transfer_worker(dev: Device, user: str, pw: str, location_name: str,
                    enable_pw: str = "") -> Dict[str, Any]:
    """Lock services, pre-check, transfer the image, hand the session over.

    The session built here is the one install_worker reuses, so ``install add``
    and ``install activate`` cannot race the install engine lock (rule P2).
    """
    host = dev.hostname
    started = time.time()
    result: Dict[str, Any] = {"ok": False, "host": host, "ip": dev.ip, "error": "",
                              "conn": None, "fw_file": "", "pre": {}, "pre_config": "",
                              "target": dev.target or TARGET_VERSION, "syntax": {},
                              "md5_ok": False, "dry_run": bool(DRY_RUN),
                              "needs_transfer": False, "model": "", "members": 1,
                              "clock_corrected": False, "duration": 0.0}
    archive_device_log(host)
    rec = new_record(dev, location_name)
    rec["start_version"] = dev.start_version
    conn = None
    try:
        set_phase(host, "QUEUE", "waiting for slot")
        if SHUTDOWN_REQ.is_set():
            result["error"] = "shutdown requested"
            return result
        set_phase(host, "PRE-CHECK", "probing ssh")
        if not ssh_reachable(dev.ip):
            result["error"] = "unreachable on tcp/22"
            update_record(host, status="FAILED", stage="PRE-CHECK",
                          error=result["error"])
            dev_log(host, "ERROR", result["error"])
            return result
        set_phase(host, "PRE-CHECK", "connecting")
        conn = do_connect(dev.ip, host, user, pw, enable_pw)
        dev.model_hint = dev.model_hint or ""
        if not ensure_priv15(conn, host):
            result["error"] = "not priv 15"
            update_record(host, status="FAILED", stage="PRE-CHECK",
                          error=result["error"])
            _disconnect(conn)
            return result
        set_phase(host, "SERVICE-LOCKS", "disabling mgmt services")
        apply_service_locks(conn, host)
        apply_exec_timeout(conn, host)

        set_phase(host, "PRE-CHECK", "reading inventory")
        pre = precheck_device(conn, host, dev.ip)
        result["pre"] = pre
        dev.model = pre.get("model") or dev.model_hint
        dev.start_version = pre.get("version") or dev.start_version
        dev.fw_file = pre.get("fw_file") or ""
        dev.target = pre.get("target") or TARGET_VERSION
        result["model"] = dev.model
        result["members"] = pre.get("members", 1)
        result["target"] = dev.target
        result["syntax"] = pre.get("syntax", classify_install_syntax(_ver_tuple(dev.start_version)))
        result["fw_file"] = dev.fw_file
        rec["model"] = dev.model
        rec["start_version"] = dev.start_version
        rec["target_version"] = dev.target
        rec["fw_file"] = dev.fw_file
        update_record(host, model=dev.model, start_version=dev.start_version,
                      target_version=dev.target, fw_file=dev.fw_file)
        if not pre.get("ok"):
            result["error"] = pre.get("error") or "precheck failed"
            update_record(host, status="FAILED", stage="PRE-CHECK",
                          error=result["error"])
            dev_log(host, "ERROR", "precheck failed: %s" % result["error"])
            _disconnect(conn)
            return result

        ssh_tune(conn, host, dev.model)
        cheap_crypto(conn, host, dev.start_version)
        if _ver_tuple(dev.start_version) != (0, 0, 0):
            result["syntax"] = classify_install_syntax(_ver_tuple(dev.start_version))

        set_phase(host, "PRE-CHECK", "clock check")
        result["clock_corrected"] = fix_clock_drift(conn, host)
        update_record(host, clock_corrected=bool(result["clock_corrected"]))

        set_phase(host, "PRE-CHECK", "backing up config")
        result["pre_config"] = backup_config(conn, host)

        on_flash = _file_on_flash(conn, host, dev.fw_file)
        need_transfer = not on_flash
        if on_flash and FIRMWARE_RECHECK_BEFORE_TRANSFER:
            dir_out = _sh(conn, "dir flash:%s" % dev.fw_file, 60, host)
            size = parse_dir_size(dir_out, dev.fw_file)
            local_size = os.path.getsize(str(FIRMWARE_DIR / dev.fw_file)) if dev.fw_file else 0
            if size is None or (local_size and abs(size - local_size) > 4096):
                dev_log(host, "WARN", "firmware on flash is incomplete (size=%s); re-transferring" % size)
                need_transfer = True
            else:
                need_transfer = False
        result["needs_transfer"] = need_transfer

        if DRY_RUN:
            result["ok"] = True
            result["dry_run"] = True
            rec["status"] = "DRY-RUN"
            rec["stage"] = "PRE-CHECK"
            dev_log(host, "OK", "dry-run: would %s %s (model=%s running=%s)"
                    % ("transfer" if need_transfer else "reuse", dev.fw_file, dev.model, dev.start_version))
            result["duration"] = round(time.time() - started, 1)
            return result

        if need_transfer:
            set_phase(host, "TRANSFER", "closing precheck session")
            _disconnect(conn)
            conn = None
            with large_guard(is_large_model(dev.model)):
                tr = transfer_firmware(dev, user, pw, dev.fw_file)
            if not tr.get("ok"):
                result["error"] = tr.get("error") or "transfer failed"
                update_record(host, status="FAILED", stage="TRANSFER",
                              error=result["error"])
                dev_log(host, "ERROR", result["error"])
                return result
            set_phase(host, "TRANSFER", "reopening session")
            conn = robust_reconnect(host, dev.ip, user, pw, enable_pw, 5, 20)
            if conn is None:
                result["error"] = "session lost after transfer"
                update_record(host, status="FAILED", stage="TRANSFER",
                              error=result["error"])
                return result

        result["ok"] = True
        result["conn"] = conn
        result["duration"] = round(time.time() - started, 1)
        return result
    except Exception as exc:
        result["error"] = classify_connect_error(exc) or \
            _one_line("%s: %s" % (type(exc).__name__, exc))
        result["conn"] = None
        dev_log(host, "ERROR", "transfer_worker crashed: %s" % traceback.format_exc(limit=3))
        update_record(host, status="FAILED", stage="TRANSFER", error=result["error"])
        _disconnect(conn)
        return result


def install_worker(dev: Device, user: str, pw: str, transfer_result: Dict[str, Any],
                   location_name: str, enable_pw: str = "") -> Tuple[bool, Device, str, float, Dict[str, Any]]:
    """Install phase for one device.  Always returns a 5-tuple, never raises."""
    started = time.time()
    host = dev.hostname
    detail: Dict[str, Any] = {"hostname": host, "location": location_name, "state": ""}
    conn = None
    try:
        if SHUTDOWN_REQ.is_set():
            return (False, dev, "shutdown requested", round(time.time() - started, 1), detail)
        if not transfer_result or not transfer_result.get("ok"):
            return (False, dev, (transfer_result or {}).get("error", "transfer failed"),
                    round(time.time() - started, 1), detail)
        if DRY_RUN or CHECK_ONLY:
            detail["dry_run"] = True
            update_record(host, status="DRY-RUN", stage="DONE")
            return (True, dev, "", round(time.time() - started, 1), detail)

        fw_file = transfer_result.get("fw_file") or dev.fw_file
        target = transfer_result.get("target") or dev.target or TARGET_VERSION
        syntax = transfer_result.get("syntax") or classify_install_syntax(_ver_tuple(dev.start_version))
        pre_config = transfer_result.get("pre_config", "")
        members = transfer_result.get("members", 1)

        conn = transfer_result.get("conn")
        # Bug B17: only reconnect when the handed-over session is really dead.
        if conn is None or not _session_is_alive(conn):
            dev_log(host, "WARN", "session handed over by transfer phase is dead; reconnecting")
            conn = _fresh_conn(conn, host, dev.ip, user, pw, enable_pw, 3, 15)
            if conn is None:
                update_record(host, status="FAILED", error="session lost before install")
                return (False, dev, "session lost before install", round(time.time() - started, 1), detail)

        # Clear whatever the transfer phase left in the channel buffer so stale
        # text can never be mistaken for install output (bug B12 family).
        _drain_and_answer_prompts(conn, 5.0)

        md5_ok = bool(transfer_result.get("md5_ok"))
        if not md5_ok and fw_file:
            set_phase(host, "MD5", "verify /md5")
            md5_ok, msg = verify_firmware_md5(conn, host, fw_file, str(FIRMWARE_DIR / fw_file))
            update_record(host, md5_ok=md5_ok)
            detail["md5"] = msg
            if not md5_ok:
                dev_log(host, "ERROR", msg)
                update_record(host, status="FAILED", error=msg)
                _disconnect(conn)
                return (False, dev, msg, round(time.time() - started, 1), detail)
            dev_log(host, "OK", msg)

        st: Dict[str, Any] = {"escalations": 0, "same": 0, "last_state": "", "attempts": 0,
                              "reloads": 0, "escalated": False, "commit_tries": 0,
                              "members": members}
        set_phase(host, "INSTALL", "state machine")
        update_record(host, install_started=True, stage="INSTALL")
        ok, err, conn = run_state_machine(conn, host, dev.ip, user, pw, target, fw_file, syntax, st)

        if err == "needs_transfer":
            detail["needs_transfer"] = True
            update_record(host, stage="TRANSFER", status="RETRY")
            _disconnect(conn)
            return (False, dev, "needs_transfer", round(time.time() - started, 1), detail)

        rebooted = conn is None
        if ok and conn is None:
            update_record(host, reboot_detected=True, stage="REBOOT")
            ok, err, conn = wait_reboot_and_verify(dev.ip, target, host, user, pw, st,
                                                   pre_config, fw_file, syntax)

        post_version = st.get("post_version") or (target if ok else "")
        update_record(host,
                      status="DONE" if ok else "FAILED",
                      stage="DONE" if ok else "INSTALL",
                      post_version=post_version,
                      attempts=st.get("attempts", 0),
                      config_diff_lines=st.get("config_diff_lines", 0),
                      verify_pending=False if ok else True,
                      duration_sec=round(time.time() - started, 1),
                      error="" if ok else err)
        detail["state"] = st.get("last_state", "")
        detail["post_version"] = post_version
        detail["rebooted"] = rebooted
        detail["attempts"] = st.get("attempts", 0)
        return (ok, dev, err if not ok else "", round(time.time() - started, 1), detail)
    except Exception as exc:
        message = _one_line("%s: %s" % (type(exc).__name__, exc))
        dev_log(host, "ERROR", "install_worker crashed: %s" % traceback.format_exc(limit=3))
        update_record(host, status="FAILED", error=message,
                      duration_sec=round(time.time() - started, 1))
        return (False, dev, message, round(time.time() - started, 1), detail)
    finally:
        _disconnect(conn)


# ===========================================================================
#  REPORTS, ROLLBACK DOC, CHECKPOINTS
# ===========================================================================
def write_location_reports(location: str, records: List[Dict[str, Any]],
                           revert_report: Optional[Dict[str, Any]] = None) -> Tuple[str, str]:
    _ensure_dir(REPORT_DIR)
    csv_path = REPORT_DIR / ("%s_%s.csv" % (location, RUN_ID))
    json_path = REPORT_DIR / ("%s_%s.json" % (location, RUN_ID))
    try:
        with open(csv_path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=RECORD_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for rec in records:
                writer.writerow({k: rec.get(k, "") for k in RECORD_FIELDS})
    except Exception as exc:
        log_master("ERROR", "csv report failed for %s: %s" % (location, exc))
    payload = {
        "run_id": RUN_ID,
        "location": location,
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "version": VERSION,
        "target_version": TARGET_VERSION,
        "devices": records,
        "revert_verify": revert_report or {},
        "totals": {
            "total": len(records),
            "done": sum(1 for r in records if r.get("status") == "DONE"),
            "failed": sum(1 for r in records if r.get("status") == "FAILED"),
        },
    }
    try:
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
    except Exception as exc:
        log_master("ERROR", "json report failed for %s: %s" % (location, exc))
    return (str(csv_path), str(json_path))


def write_rollback_doc(location: str, records: List[Dict[str, Any]]) -> str:
    path = LOG_DIR / ("ROLLBACK_%s_%s.txt" % (location, RUN_ID))
    lines = [
        "MANUAL ROLLBACK PROCEDURE -- %s -- run %s" % (location, RUN_ID),
        "=" * 78,
        "Generated: %s   orchestrator v%s" % (time.strftime("%Y-%m-%d %H:%M:%S"), VERSION),
        "",
        "A rollback is only needed if a device fails to boot or fails health checks.",
        "",
        "Per device:",
        "  1. console in (or SSH if the device is reachable)",
        "  2. 'show boot'                    note the current BOOT variable",
        "  3. 'show install summary'         note the inactive/committed packages",
        "  4. 'install rollback to committed'   (reverts to the previous committed image)",
        "  5. if the device will not boot: interrupt the boot loader and boot the old .bin",
        "  6. 'show version' / 'show switch' to confirm the fleet is stable again",
        "",
        "Old images are preserved in flash (PRESERVE_ROLLBACK), so the previous",
        "IOS-XE package is still available on each chassis.",
        "",
        "%-30s %-16s %-12s %-12s %s" % ("HOST", "STATUS", "START_VER", "POST_VER", "ERROR"),
        "-" * 100,
    ]
    for rec in records:
        lines.append("%-30s %-16s %-12s %-12s %s" % (rec.get("hostname", "")[:30],
                                                     rec.get("status", ""),
                                                     rec.get("start_version", ""),
                                                     rec.get("post_version", "") or "-",
                                                     rec.get("error", "")))
    try:
        _ensure_dir(path.parent)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except Exception as exc:
        log_master("ERROR", "rollback doc failed: %s" % exc)
    return str(path)


def save_checkpoint(location: str, records: List[Dict[str, Any]]) -> None:
    try:
        _ensure_dir(CHECKPOINT_DIR)
        path = CHECKPOINT_DIR / ("%s.json" % location)
        payload = {"run_id": RUN_ID, "location": location,
                   "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
                   "done": [r["hostname"] for r in records if r.get("status") == "DONE"],
                   "failed": [r["hostname"] for r in records if r.get("status") == "FAILED"]}
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
    except Exception:
        pass


def touch_device_checkpoint(location: str, host: str, stage: str, error: str = "") -> None:
    """Record one device's stage the moment it changes.

    A crash, a power cut or a Ctrl+Break then leaves a checkpoint that says how
    far each device actually got, instead of only what the end-of-run summary
    would have said.
    """
    if not location or not host:
        return
    try:
        _ensure_dir(CHECKPOINT_DIR)
        path = CHECKPOINT_DIR / ("%s.json" % location)
        with _CKPT_LOCK:
            data: Dict[str, Any] = {}
            if path.exists():
                try:
                    with open(path, "r", encoding="utf-8") as fh:
                        loaded = json.load(fh)
                    if isinstance(loaded, dict):
                        data = loaded
                except Exception:
                    data = {}
            stages = data.setdefault("devices", {})
            entry = stages.setdefault(host, {})
            entry["stage"] = stage
            entry["ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
            if error:
                entry["error"] = _one_line(error, 160)
            data["run_id"] = RUN_ID
            data["location"] = location
            data["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
            tmp = str(path) + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
            os.replace(tmp, str(path))
    except Exception:
        pass


def load_checkpoint(location: str) -> Dict[str, Any]:
    path = CHECKPOINT_DIR / ("%s.json" % location)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


# ===========================================================================
#  LOCATION RUN
# ===========================================================================
def _collect_install_futures(ifut: Dict[Any, Any], results: List[Tuple[Any, ...]],
                             location: str) -> None:
    pending = dict(ifut)
    while pending:
        done, not_done = wait(list(pending.keys()), timeout=30, return_when=FIRST_COMPLETED)
        for fut in done:
            dev = pending.pop(fut)
            try:
                outcome = fut.result()
            except Exception as exc:
                outcome = (False, dev, "%s: %s" % (type(exc).__name__, exc), 0.0, {})
            results.append(outcome)
            ok, d, err, dur, _detail = outcome
            set_phase(d.hostname, "DONE" if ok else "FAILED", "upgraded" if ok else (err or "failed")[:24])
            log_console("OK" if ok else "FAIL", "%s %s" % (d.hostname, "upgraded" if ok else err))
        if SHUTDOWN_REQ.is_set() and not done:
            for fut in list(pending):
                fut.cancel()
            pending = {f: d for f, d in pending.items() if not f.cancelled()}
            if not pending:
                break
    ifut.clear()


def _run_transfer_phase(devices: List[Device], ctx: RunCtx, workers: int,
                        ifut: Dict[Any, Any], results: List[Tuple[Any, ...]],
                        install_pool: ThreadPoolExecutor) -> None:
    if not devices:
        return
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(transfer_worker, dev, ctx.user, ctx.pw, ctx.location,
                               ctx.enable_pw): dev for dev in devices}
        while futures:
            done, _ = wait(list(futures.keys()), timeout=15, return_when=FIRST_COMPLETED)
            for fut in done:
                dev = futures.pop(fut)
                try:
                    tres = fut.result()
                except Exception as exc:
                    tres = {"ok": False,
                            "error": _one_line("%s: %s" % (type(exc).__name__, exc)),
                            "conn": None, "host": dev.hostname, "ip": dev.ip}
                if not tres.get("ok"):
                    update_record(dev.hostname, status="FAILED", stage="TRANSFER",
                                  error=tres.get("error", "transfer failed"))
                    set_phase(dev.hostname, "FAILED", (tres.get("error") or "transfer failed")[:24])
                    results.append((False, dev, tres.get("error", "transfer failed"), 0.0, {}))
                    continue
                if tres.get("dry_run"):
                    results.append((True, dev, "", tres.get("duration", 0.0), {"dry_run": True}))
                    continue
                fut2 = install_pool.submit(install_worker, dev, ctx.user, ctx.pw, tres,
                                           ctx.location, ctx.enable_pw)
                ifut[fut2] = dev
            if SHUTDOWN_REQ.is_set() and not done:
                break


def run_location(location: str, devices: List[Device], ctx: RunCtx,
                 skip_hosts: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Upgrade one location end to end, then revert and verify its temp config.

    Note: pending temp changes from earlier runs were already loaded once in
    main(), so this function never touches persistent recovery state.
    """
    ctx.location = location
    skip = set(skip_hosts or [])
    targets = [d for d in devices if d.hostname not in skip]
    log_master("INFO", "location %s: %d device(s) queued" % (location, len(targets)))
    previous = load_checkpoint(location)
    if previous:
        _safe_print("  %s: previous checkpoint (run %s) had %d done / %d failed"
                    % (location, previous.get("run_id", "?"),
                       len(previous.get("done", [])), len(previous.get("failed", []))))
    for dev in targets:
        set_phase(dev.hostname, "QUEUE", "queued")
        new_record(dev, location)

    results: List[Tuple[Any, ...]] = []
    ifut: Dict[Any, Any] = {}
    install_pool = ThreadPoolExecutor(max_workers=INSTALL_WORKERS, thread_name_prefix="install")
    try:
        small = [d for d in targets if not is_large_model(d.model_hint)]
        large = [d for d in targets if is_large_model(d.model_hint)]
        aborted = False
        if SERIAL_TRANSFER_LARGE_MODELS and large:
            _run_transfer_phase(small, ctx, TRANSFER_SLOTS, ifut, results, install_pool)
            _collect_install_futures(ifut, results, location)
            aborted = _abort_gate(results, location)
            if aborted:
                for dev in large:
                    update_record(dev.hostname, status="SKIPPED", error="abort gate tripped")
                    set_phase(dev.hostname, "SKIPPED", "abort gate")
                    results.append((False, dev, "abort gate tripped", 0.0, {}))
            else:
                _run_transfer_phase(large, ctx, LARGE_MODEL_PARALLEL, ifut, results, install_pool)
        else:
            _run_transfer_phase(targets, ctx, TRANSFER_SLOTS, ifut, results, install_pool)
        _collect_install_futures(ifut, results, location)

        # Retry passes.  Only transfer-phase failures qualify (see
        # retryable_failure): once `install add` has started, another attempt
        # would fight a half-finished install engine run.
        attempt = 1
        while (not aborted and not SHUTDOWN_REQ.is_set()
               and attempt < max(1, MAX_RETRIES) + 1):
            retry_devs = [dev for dev in targets
                          if dev.hostname not in skip
                          and retryable_failure(dev.hostname)]
            if not retry_devs:
                break
            attempt += 1
            log_master("WARN", "location %s: retry %d/%d for %d device(s)"
                       % (location, attempt - 1, MAX_RETRIES, len(retry_devs)))
            retry_hosts = {dev.hostname for dev in retry_devs}
            results = [r for r in results if r[1].hostname not in retry_hosts]
            for dev in retry_devs:
                update_record(dev.hostname, status="RETRY", stage="QUEUE", error="")
            SHUTDOWN_REQ.wait(RETRY_DELAY_SEC)
            if SHUTDOWN_REQ.is_set():
                break
            _run_transfer_phase(retry_devs, ctx, TRANSFER_SLOTS, ifut, results, install_pool)
            _collect_install_futures(ifut, results, location)
    finally:
        install_pool.shutdown(wait=True)

    # ---- revert the temporary service changes on EVERY device (rule P4) ----
    revert_report: Dict[str, Any] = {}
    if REVERT_TEMP_CONFIG_POST_LOCATION and not DRY_RUN:
        for dev in devices:
            with TEMP_LOCK:
                pending = list(TEMP_CHANGES.get(dev.hostname, {}).get("changes", []))
            if not pending:
                continue
            set_phase(dev.hostname, "VERIFY", "reverting temp config")
            ok_count, fail_count, clean = revert_temp_config_with_retry(
                dev.hostname, dev.ip, ctx.user, ctx.pw, ctx.enable_pw)
            revert_report[dev.hostname] = {"ok": clean, "message": "reverted %d item(s)" % ok_count,
                                           "types": sorted({c.get("type", "?") for c in pending})}
        if VERIFY_NO_TEMP_CHANGES:
            verify_report = verify_no_temp_changes(devices, ctx.user, ctx.pw, location)
            for host, entry in verify_report.items():
                revert_report.setdefault(host, entry)

    records = [rec for rec in snapshot_records() if rec.get("location") == location]
    csv_path, json_path = write_location_reports(location, records, revert_report)
    rollback = write_rollback_doc(location, records)
    save_checkpoint(location, records)
    _print_location_summary(location, records, csv_path, json_path, rollback)
    return records


def _abort_gate(results: List[Tuple[Any, ...]], location: str) -> bool:
    """Stop a doomed location run instead of burning hours on a broken batch."""
    if len(results) < ABORT_GATE_MIN_DEVICES:
        return False
    failed = sum(1 for ok, _dev, _err, _dur, _det in results if not ok and _err != "needs_transfer")
    if failed / float(len(results)) > ABORT_GATE_THRESHOLD:
        log_master("ERROR", "ABORT GATE: %d/%d devices failed in %s; stopping this location"
                   % (failed, len(results), location))
        _safe_print("  !! abort gate tripped for %s (%d/%d failed)" % (location, failed, len(results)))
        return True
    return False


def _print_location_summary(location: str, records: List[Dict[str, Any]], csv_path: str,
                            json_path: str, rollback: str) -> None:
    done = sum(1 for r in records if r.get("status") == "DONE")
    failed = sum(1 for r in records if r.get("status") == "FAILED")
    _safe_print("")
    _safe_print("  == %s ==  total=%d  done=%d  failed=%d" % (location, len(records), done, failed))
    for rec in records:
        _safe_print("    %-30s %-9s %-12s -> %-12s %s"
                    % (str(rec.get("hostname"))[:30], rec.get("status", ""),
                       rec.get("start_version", ""), rec.get("post_version", "") or "-",
                       (rec.get("error") or "")[:60]))
    _safe_print("    csv: %s" % csv_path)
    _safe_print("    json: %s" % json_path)
    _safe_print("    rollback: %s" % rollback)


# ===========================================================================
#  INVENTORY
# ===========================================================================
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _looks_like_ip(text: str) -> bool:
    return bool(_IP_RE.match((text or "").strip()))


def parse_inventory_line(line: str) -> Optional[Tuple[str, str]]:
    """Accept ``hostname,ip``, ``hostname ip``, ``ip hostname`` or a bare ip."""
    raw = (line or "").strip()
    if not raw or raw.startswith("#"):
        return None
    raw = raw.split("#")[0].strip().rstrip(",")
    if not raw:
        return None
    if "," in raw or "\t" in raw or ";" in raw or "|" in raw:
        parts = [p.strip() for p in re.split(r"[,\t;|]+", raw) if p.strip()]
    else:
        parts = raw.split()
    if not parts:
        return None
    if len(parts) == 1:
        return (parts[0], parts[0])
    first, second = parts[0], parts[1]
    if _looks_like_ip(first) and not _looks_like_ip(second):
        return (second, first)
    return (first, second)


def load_location_devices(location: str) -> List[Device]:
    path = LOCATIONS_DIR / ("%s.txt" % location)
    devices: List[Device] = []
    if not path.exists():
        log_master("WARN", "inventory file missing: %s" % path)
        _safe_print("  ! inventory file missing: %s" % path)
        return devices
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parsed = parse_inventory_line(line)
                if parsed:
                    devices.append(Device(hostname=parsed[0], ip=parsed[1], location=location,
                                          target=TARGET_VERSION))
    except Exception as exc:
        log_master("ERROR", "cannot read %s: %s" % (path, exc))
    return devices


def load_hosts_devices(hosts: List[str], location: str = "adhoc") -> List[Device]:
    devices: List[Device] = []
    for item in hosts or []:
        raw = (item or "").strip()
        if not raw:
            continue
        if "=" in raw:
            name, _, ip = raw.partition("=")
            devices.append(Device(hostname=name.strip() or ip.strip(), ip=ip.strip(), location=location))
            continue
        parsed = parse_inventory_line(raw)
        if parsed:
            devices.append(Device(hostname=parsed[0], ip=parsed[1], location=location))
    return devices


def apply_filters(devices: List[Device], limit: Any, exclude: List[str]) -> List[Device]:
    """Apply --exclude, then --limit.

    ``--limit`` accepts either a count (``--limit 20``) or a hostname list
    (``--limit SW1 SW2``); an all-digit list is read as a count, anything else
    as an explicit selection.
    """
    ex = {e.strip().lower() for e in (exclude or []) if e.strip()}
    kept: List[Device] = []
    for dev in devices:
        if dev.hostname.lower() in ex or dev.ip in ex:
            continue
        kept.append(dev)
    if not limit:
        return kept
    values = [str(v).strip() for v in (limit if isinstance(limit, (list, tuple))
                                       else [limit]) if str(v).strip()]
    if not values:
        return kept
    if len(values) == 1 and values[0].isdigit():
        return kept[:int(values[0])]
    wanted = {v.lower() for v in values}
    return [dev for dev in kept if dev.hostname.lower() in wanted]


# ===========================================================================
#  PRE-SCAN, CHECK MODE, RECOVERY, RECONCILE
# ===========================================================================
def prescan_models(devices: List[Device], ctx: RunCtx) -> Dict[str, Dict[str, Any]]:
    """Read model + version from every device (read-only).  Feeds the
    small/large phase split and the start_version column of the reports."""
    out: Dict[str, Dict[str, Any]] = {}
    if not devices:
        return out
    workers = max(1, min(TRANSFER_SLOTS, len(devices)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(peek_device, d.ip, d.hostname, ctx.user, ctx.pw,
                               ctx.enable_pw): d for d in devices}
        done_count = 0
        while futures:
            done, _ = wait(list(futures.keys()), timeout=30, return_when=FIRST_COMPLETED)
            for fut in done:
                dev = futures.pop(fut)
                try:
                    info = fut.result()
                except Exception as exc:
                    info = {"hostname": dev.hostname, "ip": dev.ip, "model": "",
                            "version": "", "error": str(exc)}
                out[dev.hostname] = info
                dev.model_hint = info.get("model", "") or ""
                dev.start_version = info.get("version", "") or ""
                if not dev.start_version:
                    dev.start_version = "unknown"
                done_count += 1
                _safe_print("  scanned %3d/%d  %-30s %-12s %s"
                            % (done_count, len(devices), dev.hostname[:30],
                               dev.start_version, info.get("model", "") or info.get("error", "")))
            if SHUTDOWN_REQ.is_set() and not done:
                break
    return out


def run_check(devices: List[Device], ctx: RunCtx) -> int:
    """--check: read-only version sweep, no configuration changes at all."""
    _safe_print("  read-only version sweep: %d device(s)" % len(devices))
    info = prescan_models(devices, ctx)
    bad = 0
    for dev in devices:
        row = info.get(dev.hostname, {})
        fw, target = pick_firmware(row.get("model", ""))
        on_target = _ver_tuple(row.get("version", "")) == _ver_tuple(target)
        mark = "OK  " if on_target else "UPGD"
        if row.get("error"):
            mark = "ERR "
            bad += 1
        _safe_print("  %s %-30s %-16s -> %-10s %s"
                    % (mark, dev.hostname[:30], row.get("version", "?"), target,
                       row.get("model", "") or row.get("error", "")))
    by_location: Dict[str, List[Device]] = {}
    for dev in devices:
        by_location.setdefault(dev.location, []).append(dev)
    for location, devs in by_location.items():
        rows = []
        for dev in devs:
            row = info.get(dev.hostname, {})
            fw, target = pick_firmware(row.get("model", ""))
            rec = {k: "" for k in RECORD_FIELDS}
            rec.update({"hostname": dev.hostname, "ip": dev.ip,
                        "status": "OK" if _ver_tuple(row.get("version", "")) == _ver_tuple(target) else "NEEDS-UPGRADE",
                        "stage": "CHECK", "start_version": row.get("version", ""),
                        "target_version": target, "fw_file": fw,
                        "post_version": row.get("version", ""), "verify_pending": False,
                        "error": row.get("error", "")})
            rows.append(rec)
        write_location_reports(location, rows, {})
    return 1 if bad else 0


def run_recovery(ctx: RunCtx, dry_run_revert: bool = False) -> int:
    """--recover / --dry-run-revert: undo temp changes left by earlier runs."""
    pending = pending_temp_changes()
    if not pending:
        _safe_print("  \u2713 no pending temp changes found in %s" % STATE_DIR)
        return 0
    _safe_print("  %d host(s) with pending temp changes:" % len(pending))
    for host, changes in sorted(pending.items()):
        types = sorted({c.get("type", "?") for c in changes})
        ip = TEMP_CHANGES.get(host, {}).get("ip", "")
        _safe_print("    %-30s ip=%-15s %s" % (host[:30], ip or "-", ", ".join(types)))
    if dry_run_revert:
        _safe_print("  dry-run-revert: nothing applied")
        return 0

    failures = 0
    for host, changes in sorted(pending.items()):
        with TEMP_LOCK:
            ip = TEMP_CHANGES.get(host, {}).get("ip", "")
        if not ip:
            _safe_print("  ! %-30s no ip recorded -- revert manually" % host[:30])
            failures += 1
            continue
        ok_count, fail_count, clean = revert_temp_config_with_retry(
            host, ip, ctx.user, ctx.pw, ctx.enable_pw)
        _safe_print("  %s %-30s reverted=%d failed=%d"
                    % ("OK " if clean else "ERR", host[:30], ok_count, fail_count))
        if not clean:
            failures += 1
    _safe_print("  recovery complete: %d host(s) still dirty" % failures)
    return 1 if failures else 0


def run_reconcile(devices: List[Device], ctx: RunCtx) -> Dict[str, Dict[str, Any]]:
    """Post-run reconcile pass: re-read every device and report what is really
    on it, so the JSON report never claims more than the device confirms."""
    out: Dict[str, Dict[str, Any]] = {}
    if not devices:
        return out
    _safe_print("")
    _safe_print("  == reconcile pass (%d device(s)) ==" % len(devices))

    def _one(dev: Device) -> Tuple[str, Dict[str, Any]]:
        conn = None
        entry: Dict[str, Any] = {"hostname": dev.hostname, "ip": dev.ip, "state": "", "version": "",
                                 "summary": {}, "error": "", "recorded_status": "", "agree": False}
        try:
            conn = do_connect(dev.ip, dev.hostname, ctx.user, ctx.pw, ctx.enable_pw, fast=True)
            state, info = classify_state(conn, dev.hostname, dev.ip, dev.target, dev.fw_file, {}, False)
            entry["state"] = state
            entry["version"] = info.get("version", "")
            entry["summary"] = info.get("summary", {})
        except Exception as exc:
            entry["error"] = "%s: %s" % (type(exc).__name__, exc)
        finally:
            _disconnect(conn)
        with RUN_RECORDS_LOCK:
            rec = RUN_RECORDS.get(dev.hostname, {})
        entry["recorded_status"] = rec.get("status", "")
        entry["agree"] = (state_ok(entry) and rec.get("status") in ("DONE", "OK"))
        return (dev.hostname, entry)

    def state_ok(entry: Dict[str, Any]) -> bool:
        return entry.get("state") in ("DONE_COMMITTED", "RUNNING_UNCOMMITTED", "RUNNING_UNKNOWN")

    workers = max(1, min(TRANSFER_SLOTS, len(devices)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_one, dev): dev for dev in devices}
        while futures:
            done, _ = wait(list(futures.keys()), timeout=30, return_when=FIRST_COMPLETED)
            for fut in done:
                dev = futures.pop(fut)
                try:
                    host, entry = fut.result()
                except Exception as exc:
                    host, entry = dev.hostname, {"hostname": dev.hostname, "ip": dev.ip,
                                                 "state": "UNKNOWN", "error": str(exc)}
                out[host] = entry
                _safe_print("    %-30s %-22s %-12s %s"
                            % (host[:30], entry.get("state", "?"), entry.get("version", "-"),
                               entry.get("error", "")))
    return out


# ===========================================================================
#  LOCK / SIGNALS / CLEANUP
# ===========================================================================
def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def acquire_lock() -> bool:
    try:
        _ensure_dir(BASE_DIR)
        if LOCK_FILE.exists():
            text = ""
            try:
                with open(str(LOCK_FILE), "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read().strip()
            except Exception:
                text = ""
            pid = 0
            for token in re.split(r"\s+", text):
                if token.isdigit():
                    pid = int(token)
                    break
            if pid and _pid_alive(pid):
                _safe_print("  ! another run is active (pid %d, %s) -- refusing to start"
                            % (pid, LOCK_FILE))
                return False
            _safe_print("  ! removing stale lock file from pid %s" % (pid or "?"))
        with open(str(LOCK_FILE), "w", encoding="utf-8") as fh:
            fh.write("%d %s" % (os.getpid(), time.strftime("%Y-%m-%d %H:%M:%S")))
        return True
    except Exception as exc:
        log_master("WARN", "could not manage lock file: %s" % exc)
        return True


def release_lock() -> None:
    try:
        if LOCK_FILE.exists():
            LOCK_FILE.unlink()
    except Exception:
        pass


def _cleanup() -> None:
    """atexit: drop orphan pscp password files and the lock file."""
    patterns = [os.path.join(tempfile.gettempdir(), "_pscp_pw_*.tmp")]
    try:
        patterns.append(str(BASE_DIR / "_pscp_pw_*.tmp"))
    except Exception:
        pass
    for pattern in patterns:
        for path in glob.glob(pattern):
            try:
                os.remove(path)
            except Exception:
                pass
    release_lock()


def _on_signal(signum: int, frame: Any) -> None:
    global SHUTDOWN_COUNT
    SHUTDOWN_COUNT += 1
    if SHUTDOWN_COUNT == 1:
        SHUTDOWN_REQ.set()
        log_master("WARN", "signal %s received; allowing workers 30s to finish" % signum)
        _safe_print("")
        _safe_print("  !! interrupt received -- finishing current device work "
                    "(press again to exit immediately)")

        def _force() -> None:
            time.sleep(30)
            if SHUTDOWN_COUNT == 1:
                log_master("ERROR", "grace period expired; forcing exit")
                _cleanup()
                os._exit(1)

        threading.Thread(target=_force, name="forced-exit", daemon=True).start()
    else:
        log_master("ERROR", "second interrupt -- immediate exit")
        _cleanup()
        os._exit(1)


# ===========================================================================
#  CLI / MAIN
# ===========================================================================
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=SCRIPT_NAME,
        description="Cisco IOS-XE fleet upgrade orchestrator v%s (target IOS-XE %s)"
                    % (VERSION, TARGET_VERSION),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--locations", nargs="+", default=list(DEFAULT_LOCATIONS),
                   help="locations to process (default: %s)" % " ".join(DEFAULT_LOCATIONS))
    p.add_argument("--hosts", nargs="+", default=None,
                   help="ad-hoc devices as name=ip (or bare ip)")
    p.add_argument("--limit", nargs="+", default=None,
                   help="process at most N devices (a number) or only these "
                        "hostnames (a list)")
    p.add_argument("--exclude", nargs="+", default=[], help="hostnames or ips to skip")
    p.add_argument("--user", default=None, help="SSH username (or $CISCO_USER)")
    p.add_argument("--enable-pass", default=None, help="enable/SSH password (or $CISCO_ENABLE)")
    p.add_argument("--enable-user", default=None,
                   help="enable username when the AAA server wants a separate "
                        "enable identity (or $CISCO_ENABLE_USER)")
    p.add_argument("--base-dir", default=None, help="override the base directory")
    p.add_argument("--config", default=None, help="explicit config.json path")
    p.add_argument("--dry-run", action="store_true", help="read-only, no device changes")
    p.add_argument("--check", action="store_true", help="read-only version sweep and exit")
    p.add_argument("--validate", action="store_true", help="run internal self-tests and exit")
    p.add_argument("--recover", action="store_true", help="revert temp config from prior runs")
    p.add_argument("--revert-only", action="store_true",
                   help="alias of --recover: revert temp config and exit")
    p.add_argument("--dry-run-revert", action="store_true",
                   help="show pending temp changes without applying them")
    p.add_argument("--yes", action="store_true", help="skip confirmation prompts")
    p.add_argument("--show-live-transfer", action="store_true",
                   help="stream pscp output into the dashboard")
    p.add_argument("--no-reconcile", action="store_true", help="skip the post-run reconcile pass")
    p.add_argument("--no-hash-verify", action="store_true",
                   help="skip MD5 verification of the transferred image")
    p.add_argument("--no-drift-check", action="store_true",
                   help="skip the post-reboot running-config drift check")
    p.add_argument("--no-serial-large", action="store_true",
                   help="interleave C9300/C9500 with the small models instead of "
                        "running them in their own slower phase")
    p.add_argument("--no-bundle-mode", action="store_true",
                   help="fail instead of converting a bundle-boot device to install mode")
    p.add_argument("--parallel-large", type=int, default=None, metavar="N",
                   help="max concurrent C9300/C9500 transfers (default: %d)"
                        % LARGE_MODEL_PARALLEL)
    p.add_argument("--version", action="store_true", help="print version and exit")
    return p


def _apply_config_file() -> None:
    """Tuning constants may be overridden from <base_dir>/config.json."""
    global LARGE_SEM
    try:
        if not CONFIG_FILE.exists():
            return
        with open(str(CONFIG_FILE), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return
        g = globals()
        for key, value in data.items():
            if key.isupper() and key in g:
                g[key] = value
                log_master("INFO", "config.json override: %s = %r" % (key, value))
        LARGE_SEM = threading.BoundedSemaphore(max(1, int(LARGE_MODEL_PARALLEL)))
    except Exception as exc:
        _safe_print("  ! config.json ignored: %s" % exc)


def _ensure_dirs() -> None:
    for path in (BASE_DIR, FIRMWARE_DIR, LOCATIONS_DIR, LOG_DIR, BACKUP_DIR,
                 REPORT_DIR, STATE_DIR, CHECKPOINT_DIR, LOG_DIR / "archive"):
        _ensure_dir(path)


def prune_old_artefacts() -> Dict[str, int]:
    """Keep logs and config backups bounded on a long-lived orchestrator box.

    A 500 device fleet writes a per-device log, an archive copy and a running
    config snapshot per run; without a retention policy the disk fills and the
    next upgrade fails for a reason that has nothing to do with the switches.
    """
    removed = {"logs": 0, "backups": 0}
    cutoff = time.time() - (LOG_MAX_AGE_DAYS * 86400)

    def _unlink(path: Path) -> None:
        try:
            path.unlink()
        except Exception:
            pass

    try:
        for path in sorted(LOG_DIR.glob("master_*.log")) + sorted(LOG_DIR.glob("ROLLBACK_*.txt")):
            try:
                if path.stat().st_mtime < cutoff:
                    _unlink(path)
                    removed["logs"] += 1
            except Exception:
                continue
        for path in sorted((LOG_DIR / "archive").glob("*.log")):
            try:
                if path.stat().st_mtime < cutoff:
                    _unlink(path)
                    removed["logs"] += 1
            except Exception:
                continue
        for pattern, cap_gb in ((LOG_DIR, LOG_MAX_SIZE_GB),):
            try:
                files = [p for p in pattern.glob("*.log") if p.is_file()]
                total = sum(p.stat().st_size for p in files)
                for path in sorted(files, key=lambda p: p.stat().st_mtime):
                    if total <= cap_gb * (1024 ** 3):
                        break
                    total -= path.stat().st_size
                    _unlink(path)
                    removed["logs"] += 1
            except Exception:
                pass
        try:
            backups = sorted((p for p in BACKUP_DIR.glob("*.cfg") if p.is_file()),
                             key=lambda p: p.stat().st_mtime)
            total = sum(p.stat().st_size for p in backups)
            keep_from = max(0, len(backups) - BACKUP_MAX_FILES)
            for index, path in enumerate(backups):
                over_count = index < keep_from
                over_size = total > BACKUP_MAX_SIZE_GB * (1024 ** 3)
                if not (over_count or over_size):
                    break
                total -= path.stat().st_size
                _unlink(path)
                removed["backups"] += 1
        except Exception:
            pass
    except Exception as exc:
        log_master("WARN", "retention sweep skipped: %s" % exc)
    if removed["logs"] or removed["backups"]:
        log_master("INFO", "retention: removed %d log file(s), %d backup(s)"
                   % (removed["logs"], removed["backups"]))
    return removed


def resolve_credentials(args: argparse.Namespace) -> Tuple[str, str, str]:
    user = args.user or os.environ.get("CISCO_USER", "")
    pw = os.environ.get("CISCO_PASS", "") or (args.enable_pass or "")
    enable = args.enable_pass or os.environ.get("CISCO_ENABLE", "") or pw
    if not user:
        try:
            user = input("SSH username: ").strip()
        except Exception:
            user = ""
    if not pw:
        try:
            import getpass
            pw = getpass.getpass("SSH password: ")
        except Exception:
            pw = ""
    if not enable:
        enable = pw
    if args.enable_user and args.enable_user != user:
        _safe_print("  note: --enable-user differs from --user; netmiko uses a single login "
                    "and 'enable' reuses the same credentials")
    return (user, pw, enable)


def build_device_list(args: argparse.Namespace) -> List[Device]:
    devices: List[Device] = []
    if args.hosts:
        devices = load_hosts_devices(args.hosts)
    else:
        for location in args.locations:
            devices.extend(load_location_devices(location))
    devices = apply_filters(devices, args.limit, args.exclude)
    return devices


def confirm(prompt: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    try:
        answer = input("%s [y/N] " % prompt).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("y", "yes")


def _revert_leftovers_outside_inventory(devices: List[Device], ctx: RunCtx) -> None:
    """Best effort revert for hosts that carry state but were not in this run."""
    known = {d.hostname for d in devices}
    for host, changes in sorted(pending_temp_changes().items()):
        if host in known:
            continue
        ip = TEMP_CHANGES.get(host, {}).get("ip", "")
        if not ip:
            _safe_print("  ! %s still has temp changes and no recorded ip" % host)
            continue
        _safe_print("  reverting leftover temp changes on %s (%s)" % (host, ip))
        ok_count, fail_count, clean = revert_temp_config_with_retry(
            host, ip, ctx.user, ctx.pw, ctx.enable_pw)
        _safe_print("     -> reverted=%d failed=%d" % (ok_count, fail_count))


def main(argv: Optional[List[str]] = None) -> int:
    global RUN_ID, LIVE_TRANSFER, DRY_RUN, CHECK_ONLY, NO_RECONCILE, DASHBOARD_ENABLED, CONSOLE_ECHO

    _init_stdout()
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.version:
        _safe_print("%s v%s (target IOS-XE %s)" % (SCRIPT_NAME, VERSION, TARGET_VERSION))
        return 0
    if args.validate:
        return run_validation()

    if args.base_dir:
        update_paths(args.base_dir)
    if args.config:
        globals()["CONFIG_FILE"] = Path(args.config).expanduser()
    _apply_config_file()

    # Bug B6: Ctrl+Break on Windows raises SIGBREAK, not SIGINT.
    for sig_name in ("SIGINT", "SIGTERM", "SIGBREAK", "SIGHUP"):
        sig = getattr(signal, sig_name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, _on_signal)
        except Exception:
            pass
    atexit.register(_cleanup)

    RUN_ID = time.strftime("%Y%m%d_%H%M%S")
    DRY_RUN = bool(args.dry_run)
    CHECK_ONLY = bool(args.check)
    NO_RECONCILE = bool(args.no_reconcile)
    LIVE_TRANSFER = bool(args.show_live_transfer)
    CONSOLE_ECHO = True
    DASHBOARD_ENABLED = not bool(args.check)

    # Optional tuning knobs that map straight onto module constants.
    globals()["SERIAL_TRANSFER_LARGE_MODELS"] = not bool(args.no_serial_large)
    globals()["VERIFY_TRANSFER_HASH"] = not bool(args.no_hash_verify)
    globals()["SKIP_CONFIG_DRIFT_CHECK"] = bool(args.no_drift_check)
    globals()["ALLOW_BUNDLE_MODE_CONVERSION"] = not bool(args.no_bundle_mode)
    if args.parallel_large is not None:
        globals()["LARGE_MODEL_PARALLEL"] = max(1, int(args.parallel_large))
        globals()["LARGE_SEM"] = threading.BoundedSemaphore(
            max(1, int(args.parallel_large)))

    _ensure_dirs()
    try:
        pruned = prune_old_artefacts()
        if pruned.get("logs") or pruned.get("backups"):
            _safe_print("  retention: removed %d log file(s), %d backup(s)"
                        % (pruned.get("logs", 0), pruned.get("backups", 0)))
    except Exception:
        pass
    if not acquire_lock():
        return 2
    try:
        globals()["ENABLE_PASSWORD"] = (os.environ.get("CISCO_ENABLE")
                                        or args.enable_pass or None)
        globals()["ENABLE_USER"] = (args.enable_user
                                    or os.environ.get("CISCO_ENABLE_USER")
                                    or None)
        user, pw, enable_pw = resolve_credentials(args)
        if not user or not pw:
            _safe_print("  ! no credentials supplied (--user / --enable-pass or "
                        "$CISCO_USER / $CISCO_PASS)")
            return 2
        ctx = RunCtx(user=user, pw=pw, enable_pw=enable_pw, run_id=RUN_ID)

        devices = build_device_list(args) if not (args.recover or args.dry_run_revert) else []

        # Bug B7: recovery state is loaded exactly once, here.
        loaded = load_state_for_recovery()
        if loaded:
            _safe_print("  %d host(s) carry pending temp changes from earlier runs" % loaded)

        # --recover / --dry-run-revert work from persisted state alone, so they
        # deliberately do not need an inventory file to be present.
        if args.dry_run_revert:
            return run_recovery(ctx, dry_run_revert=True)
        if args.recover or args.revert_only:
            return run_recovery(ctx, dry_run_revert=False)

        if not devices:
            _safe_print("  ! no devices selected -- check --locations / --hosts / --limit")
            return 2

        if CHECK_ONLY:
            return run_check(devices, ctx)

        fw_ok, fw_errors, fw_warnings = preflight_firmware()
        for warning in fw_warnings:
            _safe_print("  ! firmware: %s" % warning)
        if fw_errors and not DRY_RUN:
            _safe_print("")
            _safe_print("  !! firmware pre-flight failed:")
            for error in fw_errors:
                _safe_print("     - %s" % error)
            _safe_print("     firmware dir: %s" % FIRMWARE_DIR)
            return 2

        _safe_print("  %s v%s  run %s" % (SCRIPT_NAME, VERSION, RUN_ID))
        _safe_print("  base dir : %s" % BASE_DIR)
        _safe_print("  locations: %s" % ", ".join(args.locations if not args.hosts else ["adhoc"]))
        _safe_print("  devices  : %d" % len(devices))
        _safe_print("  firmware : %d image(s) verified in %s"
                    % (len(FIRMWARE_SIZES), FIRMWARE_DIR))
        _safe_print("  target   : IOS-XE %s (%d transfer slots, %d install workers, "
                    "%d large-model slots)"
                    % (TARGET_VERSION, TRANSFER_SLOTS, INSTALL_WORKERS,
                       LARGE_MODEL_PARALLEL))
        applied = ", ".join(PARAMIKO_REPORT.get("applied") or ["defaults"])
        _safe_print("  paramiko : %s [%s]" % (PARAMIKO_REPORT.get("paramiko"), applied))
        if not PARAMIKO_REPORT.get("legacy_kex"):
            _safe_print("  ! this paramiko cannot offer dh-group14-sha1 / "
                        "ssh-rsa; switches older than IOS-XE 16.12 may refuse "
                        "the handshake (install paramiko < 5 or upgrade the "
                        "switch to 16.12+)")
        if DRY_RUN:
            _safe_print("  mode     : DRY RUN (no device changes)")
        if not confirm("begin upgrade?", args.yes):
            _safe_print("  aborted by operator")
            return 1

        log_master("INFO", "run %s starting: %d device(s), dry_run=%s"
                   % (RUN_ID, len(devices), DRY_RUN))

        dash = threading.Thread(target=dashboard_thread, name="dashboard", daemon=True)
        dash.start()

        _safe_print("  pre-scanning models/versions ...")
        prescan_models(devices, ctx)

        all_records: List[Dict[str, Any]] = []
        by_location: Dict[str, List[Device]] = {}
        for dev in devices:
            by_location.setdefault(dev.location or "adhoc", []).append(dev)

        for location, devs in by_location.items():
            if SHUTDOWN_REQ.is_set():
                _safe_print("  shutdown requested -- skipping %s" % location)
                break
            all_records.extend(run_location(location, devs, ctx))

        _revert_leftovers_outside_inventory(devices, ctx)

        if not NO_RECONCILE and not SHUTDOWN_REQ.is_set() and not DRY_RUN:
            reconcile = run_reconcile(devices, ctx)
            try:
                path = REPORT_DIR / ("reconcile_%s.json" % RUN_ID)
                with open(str(path), "w", encoding="utf-8") as fh:
                    json.dump(reconcile, fh, indent=2, default=str)
            except Exception:
                pass

        done = sum(1 for r in all_records if r.get("status") == "DONE")
        failed = sum(1 for r in all_records if r.get("status") == "FAILED")
        drx = sum(1 for r in all_records if r.get("status") == "DRY-RUN")
        _safe_print("")
        _safe_print("  ================= final summary (run %s) =================" % RUN_ID)
        _safe_print("  devices=%d  done=%d  failed=%d  dry-run=%d"
                    % (len(all_records), done, failed, drx))
        _safe_print("  logs     : %s" % LOG_DIR)
        _safe_print("  reports  : %s" % REPORT_DIR)
        _safe_print("  backups  : %s" % BACKUP_DIR)
        log_master("INFO", "run %s finished: done=%d failed=%d" % (RUN_ID, done, failed))
        if all_records and failed == 0:
            return 0
        return 1 if failed else 0
    finally:
        SHUTDOWN_REQ.set()
        release_lock()


# ===========================================================================
#  VALIDATION MODE  --  one self-test per regression in the bug history
# ===========================================================================
def run_validation(verbose: bool = True) -> int:
    _init_stdout()
    tests: List[Tuple[str, Callable[[], bool]]] = []

    def add(name: str, fn: Callable[[], bool]) -> None:
        tests.append((name, fn))

    def t_version_string() -> bool:
        return bool(VERSION)

    def t_classify_176() -> bool:
        return classify_install_syntax((17, 6, 4))["activate_form"] == "either"

    def t_classify_1718() -> bool:
        return classify_install_syntax((17, 18, 4))["activate_form"] == "file"

    def t_build_file_activate() -> bool:
        cmds = build_activate_cmds("x.bin", {"activate_form": "file"})
        return cmds == ["install activate file flash:x.bin"]

    def t_apply_service_locks() -> bool:
        src = inspect.getsource(apply_service_locks)
        return all(key in src for key in ("http_server", "https_server", "tftp_server", "scp_server"))

    def t_revert_services() -> bool:
        src = inspect.getsource(revert_temp_config)
        return all(key in src for key in ("http_server", "https_server", "tftp_server", "scp_server"))

    def t_verify_no_temp() -> bool:
        return "on-target" in inspect.getsource(verify_no_temp_changes)

    def t_locks_before_precheck() -> bool:
        src = inspect.getsource(transfer_worker)
        return src.index("apply_service_locks") < src.index("precheck_device")

    def t_no_per_location_state() -> bool:
        return "load_state_for_recovery" not in inspect.getsource(run_location)

    def t_pscp_reader_thread() -> bool:
        src = inspect.getsource(_pscp_run_once)
        return ("threading.Thread" in src and "queue.Queue" in src and "q.get(timeout=" in src)

    def t_keepalive() -> bool:
        src = inspect.getsource(do_connect)
        return "get_transport()" in src and "getattr" not in src

    def t_escalation_cap_top() -> bool:
        src = inspect.getsource(run_state_machine)
        return src.index("MAX_ESCALATIONS") < src.index("classify_state")

    def t_update_paths_from_main() -> bool:
        return "update_paths" in inspect.getsource(main)

    def t_session_is_alive_loops() -> bool:
        return "3.0" in inspect.getsource(_session_is_alive)

    def t_sigbreak() -> bool:
        return "SIGBREAK" in inspect.getsource(main)

    def t_settle_shutdown_aware() -> bool:
        return "SHUTDOWN_REQ.wait(POST_REBOOT_SETTLE_SEC)" in inspect.getsource(wait_reboot_and_verify)

    def t_normalise_status() -> bool:
        return _normalise_status("(C)") == "C" and _normalise_status("[C]") == "C"

    def t_remote_size_retries() -> bool:
        return "range(2)" in inspect.getsource(_remote_file_size)

    def t_ntp_socket_cleanup() -> bool:
        src = inspect.getsource(_fetch_reference_utc)
        return "finally" in src and "s.close()" in src

    def t_summary_parser_rows() -> bool:
        return _parse_install_summary("  IMG  C  17.18.04") == {"17.18.04": "C"}

    add("VERSION_STRING", t_version_string)
    add("classify 17.6.4", t_classify_176)
    add("classify 17.18.4", t_classify_1718)
    add("build file-arg activate", t_build_file_activate)
    add("apply_service_locks", t_apply_service_locks)
    add("revert handles services", t_revert_services)
    add("verify_no_temp_changes", t_verify_no_temp)
    add("locks before precheck", t_locks_before_precheck)
    add("run_location no per-loc", t_no_per_location_state)
    add("pscp reader thread", t_pscp_reader_thread)
    add("keepalive get_transport", t_keepalive)
    add("escalation cap top", t_escalation_cap_top)
    add("update_paths from main", t_update_paths_from_main)
    add("session_is_alive loops", t_session_is_alive_loops)
    add("SIGBREAK registered", t_sigbreak)
    add("settle shutdown-aware", t_settle_shutdown_aware)
    add("normalise_status", t_normalise_status)
    add("remote_size retries", t_remote_size_retries)
    add("NTP socket cleanup", t_ntp_socket_cleanup)
    add("summary parser rows", t_summary_parser_rows)

    passed = 0
    failures: List[str] = []
    if verbose:
        _safe_print("  self-test suite for %s v%s" % (SCRIPT_NAME, VERSION))
    for name, fn in tests:
        try:
            ok = bool(fn())
            detail = ""
        except Exception as exc:
            ok = False
            detail = "%s: %s" % (type(exc).__name__, exc)
        if ok:
            passed += 1
            if verbose:
                _safe_print("  \u2713 %s" % name)
        else:
            failures.append(name)
            if verbose:
                _safe_print("  \u2717 %s%s" % (name, (" -- " + detail) if detail else ""))
    if verbose:
        _safe_print("Passed: %d/%d" % (passed, len(tests)))
        if failures:
            _safe_print("failed: %s" % ", ".join(failures))
    return 0 if passed == len(tests) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        SHUTDOWN_REQ.set()
        _cleanup()
        sys.exit(130)
    except Exception:
        _safe_print("FATAL: %s" % traceback.format_exc())
        _cleanup()
        sys.exit(3)
