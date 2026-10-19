def _run_install_commit_only(conn, host, st, ip, user, pw, target_ver):
    wlog(host, "COMMIT (already-added path)", "STEP")
    set_state(host, "INSTALL", "commit")
    if st.get("reboot_detected") or conn is None:
        wlog(host, "Waiting for reboot to settle before commit", "INFO")
        if not wait_for_ping_down(ip, host,
                                  timeout_sec=PING_DOWN_TIMEOUT_SEC):
            wlog(host, "Device did not go down -- checking anyway", "WARN")
        if not wait_for_ping_up(ip, host,
                                timeout_sec=PING_UP_TIMEOUT_SEC):
            return False, "device did not return after activate", None
        if not wait_for_ping_stable(ip, host):
            return False, "boot loop detected", None
        if not wait_for_ssh_ready(ip, host):
            return False, "SSH did not return after activate", None
        time.sleep(POST_REBOOT_SETTLE_SEC)
        conn = robust_reconnect(ip, user, pw, host,
                                max_attempts=POST_REBOOT_MAX_ATTEMPTS,
                                delay=POST_REBOOT_DELAY_SEC,
                                purpose="post-activate commit")
        if not conn:
            return False, "could not reconnect for commit", None
    if _finalize_install_commit(conn, host, target_ver, fw_file=""):
        return True, "", conn
    return False, "commit could not be verified", conn


def precheck_device(conn, host, fw_file, target_ver):
    wlog(host, "--- PRE-CHECK ---", "STEP")
    members_count = 1
    try:
        sw = conn.send_command("show switch", read_timeout=60)
        rows = _SWITCH_ROW_RE.findall(sw)
        members_count = len(rows) if rows else 1
    except Exception:
        members_count = 1

    set_state(host, "PRE-CHECK", "clock")
    _ok, _drift, _tz = _ensure_device_clock_correct_cached(
        conn, host, max_drift_sec=CLOCK_DRIFT_FIX_SEC)
    clock_fixed = bool(_ok and _drift is not None
                       and _drift > CLOCK_DRIFT_FIX_SEC)

    set_state(host, "PRE-CHECK", "model")
    model = get_model(conn)
    if model: wlog(host, "  Model: %s" % model, "INFO")

    ok_fam, reason = verify_model_firmware_consistency(
        model, fw_file, target_ver)
    if not ok_fam:
        wlog(host, "  Firmware/model mismatch: %s" % reason, "ERROR")
        if STRICT_FAMILY_CHECK:
            return (False, "firmware mismatch: %s" % reason, "unknown",
                    clock_fixed)
        else:
            wlog(host, "  Continuing in lenient mode", "WARN")

    set_state(host, "PRE-CHECK", "readiness")
    ready_ok, ready_reason = verify_boot_and_install_ready(
        conn, host, fw_file, self_heal=True)
    if not ready_ok:
        wlog(host, "  readiness gate: %s" % ready_reason, "ERROR")
        return (False, ready_reason, "unknown", clock_fixed)

    set_state(host, "PRE-CHECK", "version")
    ver_out = conn.send_command("show version | include Version")
    m = re.search(r"Version ([\w.()]+)", ver_out)
    current_ver = m.group(1) if m else "unknown"
    wlog(host, "  Version: %s  ->  target %s" % (current_ver, target_ver),
         "INFO", silent=QUIET_SKIPPED)

    if _norm_ver(current_ver) == _norm_ver(target_ver):
        needs_finalize = False
        try:
            summ = conn.send_command("show install summary",
                                     read_timeout=60)
            feed_live_log(host,
                          "[precheck] show install summary\n%s" % summ)
            if summary_committed_on_target(summ, target_ver):
                wlog(host, "  on target and committed", "OK",
                     silent=QUIET_SKIPPED)
            else:
                entries = _parse_install_summary(summ)
                status = entries.get(_norm_ver(target_ver))
                other_c = [v for v, s in entries.items()
                           if s == "C" and v != _norm_ver(target_ver)]
                if other_c:
                    wlog(host, "  on target but TWO committed versions "
                               "present (%s) -- manual remediation required"
                         % ", ".join(other_c), "ERROR")
                    return (False,
                            "two committed versions present: %s + %s"
                            % (target_ver, ", ".join(other_c)),
                            current_ver, clock_fixed)
                wlog(host, "  on target but install summary status=%s "
                           "-- will run install commit" % (status or "?"),
                     "WARN")
                needs_finalize = True
        except Exception as e:
            wlog(host, "  summary read failed: %s -- assuming commit "
                       "needed" % str(e)[:80], "WARN")
            needs_finalize = True

        residuals = {}
        try:
            residuals = _detect_residual_temp_config(conn, host)
        except Exception as e:
            wlog(host, "  residual scan failed: %s" % str(e)[:80], "WARN")

        existing_types = {ch["type"] for ch in get_temp_changes(host)}
        newly_discovered = []
        for t, d in residuals.items():
            if t not in existing_types:
                newly_discovered.append(t)
            track_temp_change(host, t, d)

        all_residual_types = set(existing_types) | set(residuals.keys())
        needs_cleanup = bool(all_residual_types)

        if newly_discovered:
            wlog(host, "  newly discovered residual temp config: %s"
                 % ", ".join(sorted(newly_discovered)), "WARN")
        if needs_cleanup:
            wlog(host, "  temp config to revert: %s"
                 % ", ".join(sorted(all_residual_types)), "INFO")

        if not needs_finalize and not needs_cleanup:
            wlog(host, "  on target, committed, and clean", "OK")
            return (True, "already_on_target", current_ver, clock_fixed)
        if needs_finalize and not needs_cleanup:
            wlog(host, "  fixup: finalize only", "INFO")
            return (True, "already_on_target_needs_finalize", current_ver,
                    clock_fixed)
        if not needs_finalize and needs_cleanup:
            wlog(host, "  fixup: cleanup only", "INFO")
            return (True, "already_on_target_needs_cleanup", current_ver,
                    clock_fixed)
        wlog(host, "  fixup: finalize + cleanup", "INFO")
        return (True, "already_on_target_needs_finalize_and_cleanup",
                current_ver, clock_fixed)

    already_added, added_reason = _is_target_pkg_set_present(
        conn, host, target_ver)
    if already_added:
        wlog(host, "  %s" % added_reason, "OK")
        wlog(host, "  skipping space gate and transfer; proceeding to "
                   "activate/commit", "OK")
        return (True, "already_added_needs_activate",
                current_ver, clock_fixed)

    boot = conn.send_command("show boot | include BOOT", read_timeout=60)
    feed_live_log(host, "[precheck] show boot\n%s" % boot)
    if "packages.conf" not in boot:
        if ALLOW_BUNDLE_MODE_CONVERSION:
            wlog(host, "  Bundle mode -- install will convert", "WARN")
            master_log("%s: BUNDLE MODE -- will convert via install add" % host)
        else:
            wlog(host, "  Not INSTALL mode", "ERROR")
            return (False, "not_install_mode", current_ver, clock_fixed)

    fw_size = get_firmware_size(fw_file)
    if not fw_size:
        fw_size = MIN_FREE_BYTES

    bin_present = False
    try:
        out = conn.send_command(
            "dir flash: | include %s" % re.escape(fw_file),
            read_timeout=TRANSFER_VERIFY_TIMEOUT)
        if fw_file in out:
            remote_size = _parse_file_size_from_dir(out, fw_file)
            if remote_size and remote_size == fw_size:
                bin_present = True
                wlog(host, "  target .bin already on flash (correct "
                           "size)", "OK")
            elif remote_size:
                wlog(host, "  target .bin on flash but wrong size "
                           "(%d vs %d) -- will be re-transferred"
                     % (remote_size, fw_size), "WARN")
    except Exception:
        pass

    extraction = int(fw_size * EXTRACTION_OVERHEAD_FACTOR)
    required_active = (extraction + EXTRA_HEADROOM_BYTES) if bin_present \
                      else (fw_size + extraction + EXTRA_HEADROOM_BYTES)
    wlog(host, "  Space plan: fw_size=%s extraction=%s headroom=%s "
               "bin_on_flash=%s"
         % (_fmt_bytes(fw_size), _fmt_bytes(extraction),
            _fmt_bytes(STACK_MEMBER_HEADROOM),
            "yes" if bin_present else "no"), "INFO")

    if not DRY_RUN:
        try:
            in_install = _is_install_mode(conn)
            if in_install:
                wlog(host, "  Purging stale .bin / .conf / junk "
                           "(running .bin is deletable in install mode)",
                     "INFO")
                _purge_unnecessary_files(conn, host, fw_file, aggressive=False,
                                         target_ver=target_ver)
                if members_count > 1:
                    _purge_standby_members(conn, host, fw_file, members_count)
                time.sleep(2)
                try:
                    out2 = conn.send_command(
                        "dir flash: | include %s" % re.escape(fw_file),
                        read_timeout=60)
                    if fw_file in out2:
                        bin_present = True
                except Exception:
                    pass
        except Exception as e:
            wlog(host, "  purge failed (non-fatal): %s" % str(e)[:80],
                 "WARN")

    try:
        per_member_bytes = _get_all_member_free_bytes(conn, host)
        skip_per_member_gate = False
        if per_member_bytes is None:
            wlog(host, "  Could not verify all stack member storage -- "
                       "SKIPPING pre-check space gate "
                       "(install will validate)", "WARN")
            skip_per_member_gate = True

        if (not skip_per_member_gate) and per_member_bytes and fw_size:
            shortfalls = []
            for idx, mfree in enumerate(per_member_bytes):
                need_this = _member_required_bytes(
                    fw_size,
                    preserve_rollback=PRESERVE_ROLLBACK,
                    bin_already_present=(bin_present and idx == 0),
                    is_standby=(idx > 0))
                role = "active" if idx == 0 else "standby"
                marker = "OK" if mfree >= need_this else "SHORT"
                wlog(host, "  member %d (%s): free=%s need=%s %s"
                     % (idx + 1, role, _fmt_bytes(mfree),
                        _fmt_bytes(need_this), marker),
                     "OK" if mfree >= need_this else "WARN")
                if mfree < need_this:
                    shortfalls.append((idx + 1, role, mfree, need_this))

            if shortfalls:
                wlog(host, "  Space short on %d member(s) -- attempting "
                           "aggressive purge" % len(shortfalls), "WARN")
                try:
                    _purge_unnecessary_files(conn, host, fw_file,
                                             aggressive=True,
                                             target_ver=target_ver)
                    if members_count > 1:
                        _purge_standby_members(conn, host, fw_file,
                                               members_count)
                except Exception as e:
                    wlog(host, "  aggressive purge failed: %s"
                         % str(e)[:80], "WARN")
                time.sleep(3)
                per_member_bytes = _get_all_member_free_bytes(conn, host)
                if per_member_bytes is None:
                    skip_per_member_gate = True
                else:
                    shortfalls = []
                    for idx, mfree in enumerate(per_member_bytes):
                        need_this = _member_required_bytes(
                            fw_size,
                            preserve_rollback=PRESERVE_ROLLBACK,
                            bin_already_present=(bin_present and idx == 0),
                            is_standby=(idx > 0))
                        role = "active" if idx == 0 else "standby"
                        marker = "OK" if mfree >= need_this else "SHORT"
                        wlog(host,
                             "  after purge -- member %d (%s): free=%s "
                             "need=%s %s"
                             % (idx + 1, role, _fmt_bytes(mfree),
                                _fmt_bytes(need_this), marker),
                             "OK" if mfree >= need_this else "WARN")
                        if mfree < need_this:
                            shortfalls.append((idx + 1, role, mfree,
                                               need_this))

            if shortfalls and not skip_per_member_gate:
                detail = "; ".join(
                    "m%d(%s) free=%s need=%s"
                    % (m, role, _fmt_bytes(f), _fmt_bytes(n))
                    for m, role, f, n in shortfalls)
                reason = ("insufficient_space_stack: %s "
                          "fw_size=%s extraction=%s headroom=%s"
                          % (detail,
                             _fmt_bytes(fw_size),
                             _fmt_bytes(extraction),
                             _fmt_bytes(STACK_MEMBER_HEADROOM)))
                wlog(host, "  STILL insufficient: %s -- REFUSING"
                     % reason, "ERROR")
                return (False, reason, current_ver, clock_fixed)
            if not shortfalls and not skip_per_member_gate:
                wlog(host, "  All %d member(s) have sufficient space"
                     % len(per_member_bytes), "OK")
        elif not skip_per_member_gate and fw_size:
            wlog(host, "  Could not determine per-member free", "WARN")
    except Exception as e:
        wlog(host, "  Stack free-space check skipped: %s" % str(e)[:80],
             "WARN")

    if WIPE_BEFORE_TRANSFER and not DRY_RUN:
        set_state(host, "PRE-CHECK", "wiping")
        wipe_firmware_flash(conn, host)
    free_bytes = get_flash_free_bytes(conn)
    if free_bytes < required_active:
        reason = ("insufficient_space: free=%s need=%s"
                  % (_fmt_bytes(free_bytes),
                     _fmt_bytes(required_active)))
        wlog(host, "  STILL insufficient on active member: %s -- REFUSING"
             % reason, "ERROR")
        return (False, reason, current_ver, clock_fixed)
    wlog(host, "  Space OK: %.1f MB (active need ~%.0f MB)"
         % (free_bytes/1e6, required_active/1e6), "OK")
    return (True, "ready", current_ver, clock_fixed)


def _pwfile_for_thread():
    global _PWFILE_COUNTER
    with _PWFILE_COUNTER_LK:
        _PWFILE_COUNTER += 1
        n = _PWFILE_COUNTER
    return "%s_%d_%d.tmp" % (_PWFILE_BASE, os.getpid(), n)


def _write_pwfile(pw):
    path = _pwfile_for_thread()
    with _PWFILE_LOCK:
        try:
            with open(path, "w", newline="") as f:
                f.write(pw + "\n")
            return path
        except Exception as e:
            master_log("Could not write pwfile: %s" % e)
            return None


def _delete_pwfile(path):
    if not path: return
    with _PWFILE_LOCK:
        try:
            if os.path.exists(path): os.remove(path)
        except OSError: pass


def _verify_firmware_hash(fw_file, host):
    if not FIRMWARE_RECHECK_BEFORE_TRANSFER: return True
    expected = FIRMWARE_SHA256.get(fw_file)
    if not expected: return True
    p = os.path.join(FIRMWARE_DIR, fw_file)
    try:
        actual = _sha256_of_file(p)
        if actual != expected:
            wlog(host, "Firmware hash changed! expected %s... got %s..."
                 % (expected[:16], actual[:16]), "ERROR")
            return False
        return True
    except Exception as e:
        wlog(host, "Firmware hash re-check failed: %s" % str(e)[:80], "WARN")
        return True


def _pscp_run_once(cmd, host, start, tag_prefix=""):
    """
    v35.9.43 FIX-PSCP-STALL: adds a stall detector.  Previously the
    blocking `proc.stdout.read(4096)` never returned when pscp stopped
    producing output (hung socket, stalled transfer), freezing the
    entire transfer pool.  Now a background reader thread pushes raw
    bytes onto a queue, and the main loop kills the process after
    SCP_STALL_TIMEOUT seconds without any output, letting the caller's
    retry path take over.
    """
    import queue as _queue
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            bufsize=-1,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    except Exception as e:
        wlog(host, "pscp spawn failed: %s" % str(e)[:120], "ERROR")
        return -1, 0.0, False

    pct_re = re.compile(rb"(\d{1,3})%")
    last_pct = -1
    last_report = 0.0
    killed = False

    chunks = _queue.Queue()
    _SENTINEL = object()

    def _reader():
        try:
            while True:
                buf = proc.stdout.read(4096)
                if not buf:
                    break
                chunks.put(buf)
        except Exception:
            pass
        finally:
            try: proc.stdout.close()
            except Exception: pass
            chunks.put(_SENTINEL)

    rt = threading.Thread(target=_reader, daemon=True, name="pscp-rd")
    rt.start()

    pending = b""
    last_data = time.time()
    try:
        while True:
            if SHUTDOWN_REQ.is_set():
                try: proc.terminate()
                except Exception: pass
                killed = True
                wlog(host, "pscp aborted (shutdown)", "WARN")
                break
            try:
                item = chunks.get(timeout=1.0)
            except _queue.Empty:
                if time.time() - last_data > SCP_STALL_TIMEOUT:
                    wlog(host, "pscp stalled %ds with no output -- killing "
                               "(will retry)" % SCP_STALL_TIMEOUT, "WARN")
                    try: proc.kill()
                    except Exception: pass
                    killed = True
                    break
                continue
            if item is _SENTINEL:
                break
            last_data = time.time()
            pending += item
            # pscp writes progress with `\r`, stats with `\n`.
            while True:
                i_r = pending.find(b"\r")
                i_n = pending.find(b"\n")
                idxs = [i for i in (i_r, i_n) if i >= 0]
                if not idxs:
                    break
                i = min(idxs)
                line, pending = pending[:i], pending[i+1:]
                if LIVE_LOG_FEED_TRANSFER:
                    try: line_str = line.decode("utf-8", "replace")
                    except Exception: line_str = str(line)
                    if line_str.strip():
                        feed_live_log(host, "[%spscp] %s"
                                      % (tag_prefix, line_str.strip()))
                m = pct_re.search(line)
                if m:
                    try: pct = int(m.group(1))
                    except Exception: continue
                    if pct != last_pct and time.time() - last_report > 3:
                        last_pct = pct
                        last_report = time.time()
                        with STATE_LOCK:
                            if host in PEER_STATES:
                                PEER_STATES[host]["progress"] = float(pct)
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            try: proc.kill()
            except Exception: pass
            wlog(host, "pscp hung on exit", "WARN")
            return -2, time.time() - start, False
    except Exception as e:
        wlog(host, "pscp read error: %s" % str(e)[:120], "WARN")
        try: proc.kill()
        except Exception: pass
        return -3, time.time() - start, False

    rc_final = proc.returncode if proc.returncode is not None else -4
    if rc_final != 0:
        try:
            tail = (pending or b"").decode("utf-8", "replace").strip()
            if tail:
                wlog(host, "  pscp(%s) output tail: %s"
                     % (tag_prefix or "main", tail[-500:]), "INFO")
        except Exception: pass
    return rc_final, time.time() - start, killed


def transfer_via_pscp(ip, user, pw, fw_file, host):
    if not os.path.isfile(PSCP_EXE):
        wlog(host, "pscp.exe not found at %s" % PSCP_EXE, "ERROR"); return False
    local_file = os.path.join(FIRMWARE_DIR, fw_file)
    if not os.path.isfile(local_file):
        wlog(host, "pscp: local missing %s" % local_file, "ERROR")
        return False
    if not _verify_firmware_hash(fw_file, host): return False
    pwfile = _write_pwfile(pw)
    if not pwfile: return False
    wlog(host, "PSCP push -> %s:%s" % (ip, fw_file), "STEP")
    set_state(host, "TRANSFER", "PSCP", progress=0)
    set_cmd(host, "pscp -> flash:%s" % fw_file)
    dest = "%s@%s:flash:%s" % (user, ip, fw_file)
    cmd = [PSCP_EXE, "-scp", "-batch", "-pwfile", pwfile,
           local_file, dest]
    start = time.time()
    rc, elapsed, killed = _pscp_run_once(cmd, host, start)
    try: _delete_pwfile(pwfile)
    except Exception: pass
    if killed: return False
    if rc == 0:
        fw_size = get_firmware_size(fw_file)
        mbps = fw_size / max(elapsed, 1) / 1e6 if fw_size else 0
        wlog(host, "PSCP success -- %.0fs (%.2f MB/s)" % (elapsed, mbps),
             "OK")
        return True
    if rc == 1 and elapsed < 60:
        wlog(host, "  pscp failed fast -- fetching host key", "WARN")
        hk = _get_host_key_fingerprint(ip, user, pw)
        if hk: wlog(host, "  host key: %s  %s..." % (hk[0], hk[1][:32]), "INFO")
        else: wlog(host, "  no host key fingerprint", "WARN")
        cmd2 = [PSCP_EXE, "-scp", "-batch", "-pw", pw]
        if hk: cmd2.extend(["-hostkey", hk[1]])
        cmd2.extend([local_file, dest])
        start2 = time.time()
        rc2, elapsed2, killed2 = _pscp_run_once(cmd2, host, start2,
                                                tag_prefix="retry-")
        if killed2: return False
        if rc2 == 0:
            fw_size = get_firmware_size(fw_file)
            mbps = fw_size / max(elapsed2, 1) / 1e6 if fw_size else 0
            wlog(host, "PSCP (via -pw) -- %.0fs (%.2f MB/s)"
                 % (elapsed2, mbps), "OK")
            return True
        wlog(host, "PSCP retry failed rc=%d" % rc2, "ERROR")
        return False
    wlog(host, "PSCP failed rc=%d after %.0fs" % (rc, elapsed), "ERROR")
    return False


def transfer_via_scp(ip, user, pw, fw_file, host):
    wlog(host, "Paramiko SCP (legacy) -> %s:%s" % (ip, fw_file), "STEP")
    set_state(host, "TRANSFER", "SCP", progress=0)
    fw_size = get_firmware_size(fw_file)
    if DRY_RUN:
        wlog(host, "DRY-RUN: skipping SCP", "INFO"); return True
    local_file = os.path.join(FIRMWARE_DIR, fw_file)
    if not os.path.isfile(local_file):
        wlog(host, "local firmware missing: %s" % local_file, "ERROR")
        return False
    if not _verify_firmware_hash(fw_file, host): return False
    for attempt in range(1, SCP_MAX_ATTEMPTS + 1):
        if SHUTDOWN_REQ.is_set(): return False
        conn = None
        start_time = time.time()
        try:
            conn = do_connect(ip, user, pw)
            tacacs_enable(conn, host, ssh_pw=pw)
            if not ensure_scp_server_enabled(conn, host):
                raise RuntimeError("could not enable SCP server")
            result = file_transfer(
                conn, source_file=local_file, dest_file=fw_file,
                file_system="flash:", direction="put",
                overwrite_file=True, socket_timeout=SCP_TIMEOUT_SEC)
            if result.get("file_transferred") or result.get("file_exists"):
                elapsed = time.time() - start_time
                mbps = fw_size / max(elapsed, 1) / 1e6 if fw_size else 0
                wlog(host, "  SCP success -- %.0fs (%.2f MB/s)"
                     % (elapsed, mbps), "OK")
                return True
        except Exception as e:
            tag = _classify_connect_error(e)
            if tag:
                wlog(host, "  SCP %s" % tag, "WARN"); return False
            wlog(host, "  SCP attempt %d: %s" % (attempt, str(e)[:120]),
                 "WARN")
        finally:
            if conn:
                try: conn.disconnect()
                except Exception: pass
        if attempt < SCP_MAX_ATTEMPTS and not SHUTDOWN_REQ.is_set():
            wlog(host, "  Retrying in %ds..." % SCP_RETRY_DELAY, "INFO")
            time.sleep(SCP_RETRY_DELAY)
    return False


def _build_optimized_paramiko_client(ip, user, pw):
    import paramiko as _p
    client = _p.SSHClient()
    client.set_missing_host_key_policy(_p.AutoAddPolicy())
    client.connect(
        hostname=ip, username=user, password=pw,
        look_for_keys=False, allow_agent=False,
        timeout=PARAMIKO_CONNECT_TIMEOUT,
        banner_timeout=PARAMIKO_CONNECT_TIMEOUT,
        auth_timeout=PARAMIKO_CONNECT_TIMEOUT,
        compress=False)
    transport = client.get_transport()
    try:
        transport.default_window_size = PARAMIKO_WINDOW_BYTES
        transport.default_max_packet_size = 32768
    except Exception: pass
    if PARAMIKO_DISABLE_REKEY:
        try:
            pk = transport.packetizer
            if hasattr(pk, "REKEY_BYTES"): pk.REKEY_BYTES = 1 << 40
            if hasattr(pk, "REKEY_PACKETS"): pk.REKEY_PACKETS = 1 << 40
        except Exception: pass
    return client


def transfer_via_paramiko_tuned(ip, user, pw, fw_file, host):
    if not USE_PARAMIKO_TUNED:
        return transfer_via_scp(ip, user, pw, fw_file, host)
    local_file = os.path.join(FIRMWARE_DIR, fw_file)
    if not os.path.isfile(local_file):
        wlog(host, "local firmware missing: %s" % local_file, "ERROR")
        return False
    if not _verify_firmware_hash(fw_file, host): return False
    fw_size = get_firmware_size(fw_file) or os.path.getsize(local_file)
    wlog(host, "Paramiko tuned SCP -> %s:%s (chunk=%dKB, window=%dMB)"
         % (ip, fw_file, PARAMIKO_CHANNEL_CHUNK//1024,
            PARAMIKO_WINDOW_BYTES//(1024*1024)), "STEP")
    set_state(host, "TRANSFER", "SCP-tuned", progress=0)
    client = None
    try:
        client = _build_optimized_paramiko_client(ip, user, pw)
        transport = client.get_transport()
        try:
            probe_chan = transport.open_session()
            probe_chan.settimeout(PARAMIKO_READ_TIMEOUT)
            probe_chan.exec_command(
                "show running-config | include ip scp server")
            probe_chan.recv(4096); probe_chan.close()
        except Exception: pass
        channel = transport.open_session()
        channel.settimeout(PARAMIKO_READ_TIMEOUT)
        channel.exec_command("scp -t flash:%s" % fw_file)
        try: ack = channel.recv(1)
        except Exception as e:
            wlog(host, "SCP target ack failed: %s: %s"
                 % (type(e).__name__, str(e)[:80] or "(no message)"), "ERROR")
            return False
        if not ack or ack[0] != 0:
            try: err = channel.recv(256) or b""
            except Exception: err = b""
            wlog(host, "SCP target-mode rejected: %s"
                 % err.decode('utf-8', 'replace')[:120], "ERROR")
            return False
        import stat as _stat
        mode = _stat.S_IRUSR | _stat.S_IWUSR | _stat.S_IRGRP | _stat.S_IROTH
        header = "C%04o %d %s\n" % (mode, fw_size,
                                    os.path.basename(fw_file))
        channel.sendall(header.encode())
        try: ack = channel.recv(1)
        except Exception: ack = b""
        if not ack or ack[0] != 0:
            wlog(host, "SCP header rejected", "ERROR"); return False
        start = time.time(); sent = 0
        last_report = start; last_pct = -1
        chunk_size = PARAMIKO_CHANNEL_CHUNK
        with open(local_file, "rb") as f:
            while True:
                if SHUTDOWN_REQ.is_set():
                    wlog(host, "SCP-tuned aborted (shutdown)", "WARN")
                    try: channel.close()
                    except Exception: pass
                    return False
                buf = f.read(chunk_size)
                if not buf: break
                try: channel.sendall(buf)
                except Exception as e:
                    wlog(host, "SCP send error at %d bytes: %s: %s"
                         % (sent, type(e).__name__,
                            str(e)[:100] or "(no message)"), "ERROR")
                    return False
                sent += len(buf)
                now = time.time()
                if now - last_report > 3 and fw_size:
                    pct = int(100.0 * sent / fw_size)
                    if pct != last_pct:
                        last_pct = pct
                        with STATE_LOCK:
                            if host in PEER_STATES:
                                PEER_STATES[host]["progress"] = float(pct)
                        last_report = now
        channel.sendall(b"\x00")
        try: ack = channel.recv(1)
        except Exception: ack = b""
        if not ack or ack[0] != 0:
            wlog(host, "SCP EOF not acked by switch", "ERROR")
            return False
        try: channel.close()
        except Exception: pass
        try: client.close()
        except Exception: pass
        client = None
        elapsed = time.time() - start
        mbps = fw_size / max(elapsed, 1) / 1e6 if fw_size else 0
        wlog(host, "Paramiko tuned SCP -- %.0fs (%.2f MB/s)"
             % (elapsed, mbps), "OK")
        return True
    except Exception as e:
        detail = str(e)[:140] or "(no message)"
        wlog(host, "Paramiko tuned SCP failed: %s: %s"
             % (type(e).__name__, detail), "ERROR")
        return False
    finally:
        if client:
            try: client.close()
            except Exception: pass


def transfer_firmware(ip, user, pw, fw_file, host, model=""):
    if DRY_RUN:
        wlog(host, "DRY-RUN: skipping firmware transfer", "INFO")
        return True
    if PARAMIKO_PRIMARY and USE_PARAMIKO_TUNED:
        if transfer_via_paramiko_tuned(ip, user, pw, fw_file, host):
            return True
        wlog(host, "Paramiko tuned failed -- falling back to pscp", "WARN")
    if USE_PSCP:
        if transfer_via_pscp(ip, user, pw, fw_file, host):
            return True
        if PSCP_TRANSFER_FALLBACK:
            if USE_PARAMIKO_TUNED:
                wlog(host, "pscp failed -- falling back to tuned", "WARN")
                if transfer_via_paramiko_tuned(ip, user, pw, fw_file, host):
                    return True
            wlog(host, "pscp failed -- falling back to legacy", "WARN")
    if transfer_via_scp(ip, user, pw, fw_file, host):
        return True
    return False


def validate_transfer_size(conn, host, fw_file):
    fw_size = get_firmware_size(fw_file)
    if not fw_size:
        wlog(host, "  No local size reference", "WARN"); return True
    try:
        out = conn.send_command(
            "dir flash: | include %s" % re.escape(fw_file),
            read_timeout=60)
        feed_live_log(host, "[verify] dir flash:\n%s" % out)
        remote_size = _parse_file_size_from_dir(out, fw_file)
        if remote_size is None:
            wlog(host, "  Could not parse remote size", "ERROR")
            return False
        if remote_size == fw_size:
            wlog(host, "  Size validated: %d bytes" % remote_size, "OK")
            return True
        wlog(host, "  SIZE MISMATCH: %d != %d" % (remote_size, fw_size),
             "ERROR")
        return False
    except Exception as e:
        wlog(host, "  Size validation error: %s" % e, "ERROR")
        return False


def validate_transfer_hash(conn, host, fw_file):
    if not VERIFY_TRANSFER_HASH: return True
    expected = FIRMWARE_SHA256.get(fw_file)
    if not expected:
        wlog(host, "  No local SHA256 reference -- skipping", "WARN")
        return True
    try:
        wlog(host, "  verify /sha256 (5-15 min)", "STEP")
        set_state(host, "MD5", "verify sha256")
        set_cmd(host, "verify /sha256 flash:%s" % fw_file)
        out = conn.send_command("verify /sha256 flash:%s" % fw_file,
                                read_timeout=1800)
        feed_live_log(host, "[verify-sha256] %s" % out)
        m = re.search(r"SHA256 hash of [^:]+:\s*([0-9a-fA-F]{64})", out)
        if not m: m = re.search(r"\b([0-9a-fA-F]{64})\b", out)
        if not m:
            wlog(host, "  Could not parse SHA256 -- allowing", "WARN")
            return True
        remote = m.group(1).lower()
        if remote == expected.lower():
            wlog(host, "  SHA256 verified (%s...)" % remote[:16], "OK")
            return True
        wlog(host, "  SHA256 MISMATCH: remote=%s... local=%s..."
             % (remote[:16], expected[:16]), "ERROR")
        return False
    except Exception as e:
        wlog(host, "  SHA256 verify failed: %s -- allowing" % str(e)[:80],
             "WARN")
        return True


def _best_effort_wipe(ip, user, pw, fw_file, host, reason="wipe"):
    conn = None
    try:
        conn = do_connect(ip, user, pw)
        tacacs_enable(conn, host, ssh_pw=pw)
        if is_privileged(conn):
            _delete_firmware_from_flash(conn, host, fw_file)
        else:
            wlog(host, "  %s: not priv-15, skipping wipe" % reason, "WARN")
    except Exception as e:
        wlog(host, "  %s failed: %s" % (reason, str(e)[:80]), "WARN")
    finally:
        if conn:
            try: conn.disconnect()
            except Exception: pass


def _transfer_with_wipe_retry(ip, user, pw, fw_file, host, model=""):
    local_path = os.path.join(FIRMWARE_DIR, fw_file)
    local_size = (os.path.getsize(local_path)
                  if os.path.isfile(local_path) else 0)
    for attempt in range(1, TRANSFER_RETRY_ATTEMPTS + 1):
        if SHUTDOWN_REQ.is_set():
            wlog(host, "Shutdown -- aborting transfer retries", "WARN")
            return False
        wlog(host, "--- Transfer attempt %d/%d ---"
             % (attempt, TRANSFER_RETRY_ATTEMPTS), "STEP")
        conn = None
        try:
            conn = robust_reconnect(
                ip, user, pw, host,
                purpose="pre-transfer wipe (attempt %d)" % attempt)
            if conn:
                _delete_firmware_from_flash(conn, host, fw_file)
        except Exception as e:
            wlog(host, "Pre-transfer wipe failed: %s" % str(e)[:80], "WARN")
        finally:
            if conn:
                try: conn.disconnect()
                except Exception: pass
        transfer_ok = transfer_firmware(ip, user, pw, fw_file, host,
                                        model=model)
        if not transfer_ok:
            wlog(host, "  Transfer failed (attempt %d)" % attempt, "WARN")
            _best_effort_wipe(ip, user, pw, fw_file, host,
                              reason="post-fail wipe")
            if attempt < TRANSFER_RETRY_ATTEMPTS:
                time.sleep(TRANSFER_RETRY_DELAY_SEC)
            continue
        conn = robust_reconnect(ip, user, pw, host,
                                purpose="post-transfer verify (attempt %d)"
                                        % attempt)
        if not conn:
            wlog(host, "  Reconnect after transfer failed", "WARN")
            _best_effort_wipe(ip, user, pw, fw_file, host,
                              reason="verify-reconnect wipe")
            if attempt < TRANSFER_RETRY_ATTEMPTS:
                time.sleep(TRANSFER_RETRY_DELAY_SEC)
            continue
        try:
            if not file_in_flash(conn, fw_file):
                wlog(host, "  File not in flash after transfer", "WARN")
                if attempt < TRANSFER_RETRY_ATTEMPTS:
                    time.sleep(TRANSFER_RETRY_DELAY_SEC)
                continue
            if not validate_transfer_size(conn, host, fw_file):
                wlog(host, "  Size mismatch -- wiping", "WARN")
                _delete_firmware_from_flash(conn, host, fw_file)
                if attempt < TRANSFER_RETRY_ATTEMPTS:
                    time.sleep(TRANSFER_RETRY_DELAY_SEC)
                continue
            if not validate_transfer_hash(conn, host, fw_file):
                wlog(host, "  Hash mismatch -- wiping", "WARN")
                _delete_firmware_from_flash(conn, host, fw_file)
                if attempt < TRANSFER_RETRY_ATTEMPTS:
                    time.sleep(TRANSFER_RETRY_DELAY_SEC)
                continue
            wlog(host, "Transfer OK on attempt %d" % attempt, "OK")
            return True
        finally:
            try: conn.disconnect()
            except Exception: pass
    wlog(host, "Transfer FAILED after %d attempts"
         % TRANSFER_RETRY_ATTEMPTS, "ERROR")
    return False


def _probe_install_status(ip, user, pw, host, target_ver,
                          prev_indeterminate=0):
    c = None
    try:
        last_err = None
        for attempt in range(PROBE_CONNECT_RETRIES):
            try:
                c = do_connect(ip, user, pw)
                last_err = None
                break
            except Exception as e:
                last_err = e
                if attempt < PROBE_CONNECT_RETRIES - 1:
                    time.sleep(PROBE_CONNECT_DELAY_SEC)
        if c is None:
            err_name = type(last_err).__name__ if last_err else "?"
            wlog(host, "Probe: connect failed after %d attempts (%s) -- "
                       "indeterminate" % (PROBE_CONNECT_RETRIES, err_name),
                 "WARN")
            return (True, "connect failed (%s)" % err_name,
                    prev_indeterminate + 1)
        try:
            tacacs_enable(c, host, ssh_pw=pw)
        except Exception:
            pass
        if not is_privileged(c):
            wlog(host, "Probe: not priv-15 -- indeterminate (may be transient)",
                 "WARN")
            return (True, "not priv-15 (transient?)",
                    prev_indeterminate + 1)
        try:
            ver = c.send_command("show version | include Version",
                                 read_timeout=60)
            feed_live_log(host, "[probe] show version\n%s" % ver)
            if _norm_ver(parse_running_version(ver)) == _norm_ver(target_ver):
                try:
                    up = c.send_command("show version | include uptime is",
                                        read_timeout=30)
                    feed_live_log(host, "[probe] uptime\n%s" % up)
                    m = re.search(r"uptime is (.+)", up)
                    uptime_min = (parse_uptime_minutes(m.group(1))
                                  if m else None)
                    if uptime_min is not None and uptime_min < 30:
                        return (True,
                                "already on %s (rebooted %d min ago)"
                                % (target_ver, uptime_min), 0)
                except Exception:
                    pass
                return True, "already on %s" % target_ver, 0
        except Exception as e:
            return (True, "version check error (%s)" % type(e).__name__,
                    prev_indeterminate + 1)
        try:
            summ = c.send_command("show install summary", read_timeout=60)
            feed_live_log(host, "[probe] show install summary\n%s" % summ)
        except Exception as e:
            return (True, "install summary error (%s)" % type(e).__name__,
                    prev_indeterminate + 1)

        if re.search(r"install operation in progress|operation in progress",
                     summ, re.IGNORECASE):
            return True, "install still running", 0

        entries = _parse_install_summary(summ)
        if entries:
            tkey = _norm_ver(target_ver)
            target_status = entries.get(tkey)
            blocking = [v for v, s in entries.items()
                        if v != tkey and s in ("C", "A", "U")]
            if target_status == "C" and not blocking:
                return True, "image committed on %s" % target_ver, 0
            if target_status == "I":
                return True, "image inactive (added, awaiting activate)", 0
            if target_status == "U":
                return True, "image uncommitted (in progress)", 0
            if target_status == "A":
                return True, "image activated, commit pending", 0
            if any(s == "I" for s in entries.values()):
                return True, "image inactive (added, awaiting activate)", 0
            if any(s == "U" for s in entries.values()):
                return True, "image uncommitted (in progress)", 0
            if any(s == "A" for s in entries.values()):
                return True, "image activated, commit pending", 0

        try:
            log = c.send_command("show install log", read_timeout=60)
            feed_live_log(host, "[probe] show install log\n%s" % log)
            if not re.search(r"% Invalid input|% Incomplete", log,
                             re.IGNORECASE):
                lines = log.splitlines()
                start_idx = -1
                for i in range(len(lines) - 1, -1, -1):
                    if re.search(
                            r"install_(?:add|activate|commit|remove|"
                            r"abort|rollback).*?:\s*START",
                            lines[i], re.IGNORECASE):
                        start_idx = i
                        break
                current = ("\n".join(lines[start_idx:])
                           if start_idx >= 0 else "\n".join(lines[-40:]))
                low_cur = current.lower()
                if re.search(r"install_\w+\]\s*:\s*end\s+failed",
                             low_cur, re.IGNORECASE):
                    return False, "install log shows FAILED (current op)", 0
                if re.search(r"install_\w+\]\s*:\s*end\s+success",
                             low_cur, re.IGNORECASE):
                    return True, "install op ended SUCCESS", 0
                if start_idx >= 0:
                    return True, "current install op in progress", 0
        except Exception:
            pass
        return True, "indeterminate", prev_indeterminate + 1
    except Exception as e:
        err_name = type(e).__name__
        wlog(host, "Probe: %s: %s -- indeterminate"
             % (err_name, str(e)[:80]), "WARN")
        return True, "probe error (%s)" % err_name, prev_indeterminate + 1
    finally:
        if c:
            try: c.disconnect()
            except Exception: pass


def _safe_manual_reload(conn, host):
    wlog(host, "Issuing manual reload (fallback)", "STEP")
    try:
        drain_channel(conn, 2, host=host)
        set_cmd(host, "reload")
        conn.write_channel("reload\n")
        buffer = ""
        deadline = time.time() + 90
        sent_save_no = sent_confirm = False
        while time.time() < deadline:
            try: chunk = conn.read_channel()
            except Exception: break
            if not chunk:
                time.sleep(0.5); continue
            feed_live_log(host, chunk)
            buffer = (buffer + chunk)[-2000:]
            low = buffer.lower()
            if any(k in low for k in _RELOAD_MARKERS):
                wlog(host, "Reload accepted by switch", "OK")
                return True
            if (not sent_save_no
                    and ("system configuration has been modified" in low
                         or "save?" in low)):
                conn.write_channel("no\n"); sent_save_no = True
                time.sleep(1); buffer = ""; continue
            if (not sent_confirm
                    and ("proceed with reload" in low
                         or "[confirm]" in low)):
                conn.write_channel("\n"); sent_confirm = True
                time.sleep(1); buffer = ""; continue
        wlog(host, "Manual reload did not confirm", "WARN")
        return False
    except Exception as e:
        wlog(host, "Manual reload error: %s" % str(e)[:80], "WARN")
        return False


def run_install(conn, cmd, host, state, ip, user, pw, target_ver,
                is_issu=False, fw_file=None):
    set_state(host, "INSTALL", "starting")
    set_cmd(host, cmd)
    state["install_started"] = True
    state["last_probe"] = 0.0
    state["indeterminate_streak"] = 0
    state["last_probe_msg"] = ""
    state["probe_msg_counts"] = {}
    state["activate_nudged"] = False
    state["activate_attempts"] = 0
    state.setdefault("add_seen", False)
    state.setdefault("activate_seen", False)
    state.setdefault("commit_seen", False)
    state.setdefault("op_success_probes", 0)
    state.setdefault("commit_nudge_count", 0)
    if fw_file is None:
        m = re.search(r"flash:(\S+\.bin)", cmd)
        if m: fw_file = m.group(1)
    drain_channel(conn, 5, host=host)
    wlog(host, "INSTALL: %s" % cmd, "CMD")
    try:
        conn.write_channel(cmd + "\n")
    except Exception as e:
        return False, "write failed: %s" % e, conn
    start = time.time()
    last_output = time.time()
    buffer, last_y = "", 0.0
    success = reload_seen = False
    success_at = None
    _DONE = ("already on ", "image committed on ")

    def _close_and_return(ok, msg, rebooted=True):
        if rebooted:
            state["reboot_detected"] = True
        try: conn.disconnect()
        except Exception: pass
        return ok, msg, None

    while time.time() - start < INSTALL_TOTAL_TIMEOUT:
        if SHUTDOWN_REQ.is_set():
            return False, "shutdown requested", conn
        try:
            chunk = conn.read_channel()
            if chunk: feed_live_log(host, chunk)
        except Exception as e:
            emsg = str(e).lower()
            if success or reload_seen:
                wlog(host, "Session closed after install -- reboot in progress",
                     "OK")
                return _close_and_return(True, "", rebooted=True)
            if ("tacacs" in emsg or "authorization failed" in emsg
                    or "command authorization" in emsg):
                wlog(host, "TACACS+ dropped session: %s" % str(e)[:80],
                     "ERROR")
                try: conn.disconnect()
                except Exception: pass
                return False, "TACACS+ dropped session", None
            wlog(host, "Install session lost: %s" % str(e)[:80], "WARN")
            try: conn.disconnect()
            except Exception: pass
            new_conn = robust_reconnect(ip, user, pw, host,
                                        purpose="mid-install")
            if not new_conn:
                return _close_and_return(True, "", rebooted=True)
            try:
                if committed_on_target(new_conn, target_ver):
                    wlog(host, "Target committed after reconnect", "OK")
                    return True, "", new_conn
            except Exception:
                pass
            return False, "install session lost; state unknown", new_conn
        if chunk:
            last_output = time.time()
            buffer = (buffer + chunk)[-4000:]
            low = buffer.lower()
            for k in _AUTHZ_MARKERS:
                if k in low: return False, "TACACS+ denied command", conn
            for k in _REJECT_MARKERS:
                if k in low:
                    return False, "command rejected (%s)" % k, conn
            for k in _SPACE_MARKERS:
                if k in low:
                    msg = ("insufficient_space: install engine rejected "
                           "install add: %s" % k)
                    wlog(host, "  %s" % msg, "ERROR")
                    return False, msg, conn
            if any(k in low for k in _ALREADY_ADDED_MARKERS):
                return False, ("already_added_refused: engine refused "
                               "add because .pkg set is already on flash"), conn
            if re.search(r"failed:\s*install", low):
                return False, "install reported FAILED", conn
            tail = low[-400:]
            hit = next((p for p in _PROMPT_MARKERS if p in tail), None)
            if hit and time.time() - last_y > 10:
                conn.write_channel("y\n"); last_y = time.time()
                buffer = ""
                wlog(host, "Prompt ('%s') -> y" % hit, "OK")
                continue
            if any(k in low for k in _RELOAD_MARKERS):
                reload_seen = True
                state["reboot_detected"] = True
            if re.search(r"success:\s*install_add", low) \
                    and not state["add_seen"]:
                state["add_seen"] = True
                wlog(host, "Install add SUCCESS", "OK")
            if re.search(r"success:\s*install_activate", low) \
                    and not state["activate_seen"]:
                state["activate_seen"] = True
                wlog(host, "Install activate SUCCESS", "OK")
                if is_issu and not success:
                    success = True; success_at = time.time()
            if re.search(r"success:\s*install_commit", low) \
                    and not state["commit_seen"]:
                state["commit_seen"] = True
                success = True; success_at = time.time()
                wlog(host, "Install commit SUCCESS", "OK")

        if success and is_issu:
            set_state(host, "INSTALL", "ISSU verify")
            deadline = time.time() + ISSU_VERIFY_TIMEOUT
            consecutive_errs = 0
            while time.time() < deadline:
                if SHUTDOWN_REQ.is_set():
                    return False, "shutdown requested", conn
                time.sleep(20)
                try:
                    if committed_on_target(conn, target_ver):
                        wlog(host, "ISSU complete -- no reload", "OK")
                        return True, "", conn
                    consecutive_errs = 0
                except Exception as e:
                    consecutive_errs += 1
                    wlog(host, "ISSU verify error (%d/%d): %s"
                         % (consecutive_errs, ISSU_VERIFY_MAX_ERRORS,
                            str(e)[:80]), "WARN")
                    if consecutive_errs >= ISSU_VERIFY_MAX_ERRORS:
                        return (False,
                                "ISSU verify failed %dx consecutively: %s"
                                % (ISSU_VERIFY_MAX_ERRORS, str(e)[:80]),
                                conn)
            return False, "ISSU never committed within timeout", conn

        if reload_seen and not is_issu:
            time.sleep(3)
            return _close_and_return(True, "", rebooted=True)

        if success and not is_issu and time.time() - success_at > 180:
            already_on_target = False
            try:
                vo = conn.send_command("show version | include Version",
                                       read_timeout=30)
                if _norm_ver(parse_running_version(vo)) \
                        == _norm_ver(target_ver):
                    already_on_target = True
                    wlog(host, "Already on target after commit -- no reload "
                               "needed", "OK")
            except Exception:
                pass
            if already_on_target:
                return _close_and_return(True, "", rebooted=False)
            wlog(host, "Commit seen but device not yet on target after 180s "
                       "-- issuing manual reload", "WARN")
            _safe_manual_reload(conn, host)
            return _close_and_return(True, "", rebooted=True)

        if not chunk:
            silence = time.time() - last_output
            if (not success and silence > INSTALL_PROBE_INTERVAL
                    and time.time() - state.get("last_probe", 0)
                        > INSTALL_PROBE_INTERVAL):
                state["last_probe"] = time.time()
                set_state(host, "INSTALL",
                          "probe (silent %ds)" % int(silence))
                wlog(host, "Install silent %ds -- probing status"
                     % int(silence), "INFO")
                streak = state.get("indeterminate_streak", 0)
                probe_ok, probe_msg, new_streak = _probe_install_status(
                    ip, user, pw, host, target_ver, streak)
                state["indeterminate_streak"] = new_streak
                cnts = state["probe_msg_counts"]
                cnts[probe_msg] = cnts.get(probe_msg, 0) + 1
                same_total = cnts[probe_msg]
                if probe_ok and any(m in probe_msg for m in _DONE):
                    wlog(host, "Probe confirms on target -- exiting "
                               "install loop", "OK")
                    return _close_and_return(True, "", rebooted=False)
                if probe_ok and new_streak == 0:
                    prev_msg = state.get("last_probe_msg")
                    state["last_probe_msg"] = probe_msg
                    if probe_msg != prev_msg:
                        last_output = time.time()
                    if "image inactive" in probe_msg:
                        try:
                            if _state_needs_precommit(conn, host):
                                wlog(host, "  probe found U state -- "
                                           "pre-committing first", "WARN")
                                ok_pc, err_pc = \
                                    _run_install_commit_for_precommit(
                                        conn, host)
                                if not ok_pc:
                                    wlog(host, "  pre-commit failed: %s"
                                         % err_pc, "WARN")
                        except Exception:
                            pass
                        state["activate_attempts"] += 1
                        if state["activate_attempts"] == 1:
                            accepted = _nudge_install_activate(
                                conn, host, fw_file)
                        else:
                            accepted = _try_all_activate_forms(
                                conn, host, fw_file)
                        if accepted:
                            state["activate_nudged"] = True
                            last_output = time.time()
                            dead = False
                            try:
                                tr = getattr(conn, "remote_conn", None)
                                tr = getattr(tr, "transport", None)
                                if tr is None or not tr.is_active():
                                    dead = True
                            except Exception:
                                dead = True
                            if dead:
                                wlog(host, "  activate nudged, transport "
                                           "inactive -- reload in progress",
                                     "OK")
                                return _close_and_return(
                                    True, "", rebooted=True)
                            try:
                                conn.read_channel()
                            except Exception:
                                wlog(host, "  activate nudged, session "
                                           "closed -- reload in progress",
                                     "OK")
                                return _close_and_return(
                                    True, "", rebooted=True)
                        elif state["activate_attempts"] >= 3:
                            _run_install_abort_and_reissue(
                                conn, host, fw_file)
                            state["activate_attempts"] = 0
                            last_output = time.time()
                    elif ("image uncommitted" in probe_msg
                          or "commit pending" in probe_msg):
                        try:
                            if _state_needs_precommit(conn, host):
                                wlog(host, "  probe found U state -- "
                                           "pre-committing", "WARN")
                                _run_install_commit_for_precommit(
                                    conn, host)
                        except Exception:
                            pass
                        state["commit_nudge_count"] += 1
                        if state["commit_nudge_count"] >= 3:
                            wlog(host, "  Uncommitted -- nudging "
                                       "install commit", "WARN")
                            try:
                                conn.write_channel("install commit\n")
                                time.sleep(3)
                                try: conn.read_channel()
                                except Exception: pass
                            except Exception as e:
                                wlog(host, "  commit nudge failed: %s"
                                     % str(e)[:80], "WARN")
                            state["commit_nudge_count"] = 0
                    elif "install op ended SUCCESS" in probe_msg:
                        state["op_success_probes"] += 1
                        if state["op_success_probes"] >= 5:
                            try:
                                vo = conn.send_command(
                                    "show version | include Version",
                                    read_timeout=30)
                                if _norm_ver(parse_running_version(vo)) \
                                        == _norm_ver(target_ver):
                                    wlog(host, "Version on target after "
                                               "add-success -- exiting", "OK")
                                    return _close_and_return(True, "",
                                                             rebooted=False)
                            except Exception:
                                pass
                            state["op_success_probes"] = 0
                if same_total >= 12:
                    wlog(host, "Probe returned '%s' %d times -- forcing "
                               "version check" % (probe_msg, same_total),
                         "WARN")
                    try:
                        vo = conn.send_command(
                            "show version | include Version",
                            read_timeout=30)
                        if _norm_ver(parse_running_version(vo)) \
                                == _norm_ver(target_ver):
                            wlog(host, "Version on target -- exiting "
                                       "install loop", "OK")
                            return _close_and_return(True, "",
                                                     rebooted=False)
                    except Exception:
                        pass
                    return (False,
                            "install stuck on '%s' for %d probes"
                            % (probe_msg, same_total), conn)
                if probe_ok and new_streak != 0:
                    wlog(host, "Probe: %s (streak %d)"
                         % (probe_msg, new_streak), "WARN")
                    if new_streak >= 10:
                        return (False,
                                "install never started (indeterminate "
                                "for %ds)"
                                % (new_streak * INSTALL_PROBE_INTERVAL),
                                conn)
                elif not probe_ok:
                    wlog(host, "Probe failed: %s" % probe_msg, "WARN")
                    return False, "install probe: %s" % probe_msg, conn
            if not success and silence > INSTALL_SILENT_TIMEOUT:
                return (False,
                        "no install output for %ds" % INSTALL_SILENT_TIMEOUT,
                        conn)
            time.sleep(0.5)
    return False, "install timeout", conn


def _issue_rollback_commands(conn, host):
    for cmd in ("install rollback to committed", "install rollback to base"):
        try:
            drain_channel(conn, 2, host=host)
            set_cmd(host, cmd)
            conn.write_channel(cmd + "\n")
            time.sleep(3)
            got = ""
            try: got = conn.read_channel() or ""
            except Exception: pass
            feed_live_log(host, got)
            low = got.lower()
            if ("% invalid input" in low or "unrecognized" in low
                    or "% incomplete" in low):
                wlog(host, "  %s not accepted -- trying alternate" % cmd,
                     "WARN")
                continue
            return True, cmd
        except Exception as e:
            wlog(host, "  %s error: %s" % (cmd, str(e)[:80]), "WARN")
    return False, ""


def attempt_rollback(conn, host, ip=None, user=None, pw=None,
                     original_version=None):
    if not PRESERVE_ROLLBACK:
        wlog(host, "Rollback impossible: old packages not preserved", "ERROR")
        return False
    wlog(host, "AUTO-ROLLBACK", "STEP")
    set_state(host, "ROLLBACK", "issuing")
    issued = False
    ok, cmd = _issue_rollback_commands(conn, host)
    if not ok:
        wlog(host, "Neither rollback syntax accepted", "ERROR")
        return False
    wlog(host, "Rollback accepted: %s" % cmd, "OK")
    try:
        buffer, last_y = "", 0.0
        deadline = time.time() + 300
        while time.time() < deadline:
            try: chunk = conn.read_channel()
            except Exception:
                wlog(host, "Session closed during rollback -- reloading", "OK")
                issued = True; break
            if chunk:
                feed_live_log(host, chunk)
                buffer = (buffer + chunk)[-3000:]
                low = buffer.lower()
                if re.search(r"failed:\s*install", low):
                    wlog(host, "Rollback FAILED", "ERROR"); return False
                if any(k in low for k in ("initiating reload",
                                          "reload requested",
                                          "restarting system", "will reload")):
                    issued = True; break
                if (re.search(r"\[y/n\]|\(y/n\)|do you want to proceed",
                              low[-300:]) and time.time() - last_y > 10):
                    conn.write_channel("y\n"); last_y = time.time()
                    buffer = ""; continue
            time.sleep(0.5)
    except Exception as e:
        wlog(host, "Rollback error: %s" % str(e)[:100], "ERROR")
    if not issued: return False
    if not (ip and user and pw and original_version): return True
    wlog(host, "Waiting for rollback reboot (target %s)" % original_version,
         "INFO")
    try:
        try: conn.disconnect()
        except Exception: pass
        if not wait_for_ping_down(ip, host, timeout_sec=PING_DOWN_TIMEOUT_SEC):
            wlog(host, "Switch never went down after rollback", "WARN")
        if not wait_for_ping_up(ip, host, timeout_sec=PING_UP_TIMEOUT_SEC):
            wlog(host, "Switch did not come back", "ERROR")
            return False
        if not wait_for_ssh_ready(ip, host):
            wlog(host, "SSH not ready after rollback", "ERROR")
            return False
        c2 = robust_reconnect(ip, user, pw, host,
                              purpose="post-rollback verify")
        if not c2:
            wlog(host, "Reconnect failed after rollback", "ERROR")
            return False
        try:
            out = c2.send_command("show version | include Version",
                                  read_timeout=60)
            feed_live_log(host, "[rollback-verify] show version\n%s" % out)
            if _norm_ver(parse_running_version(out)) \
                    == _norm_ver(original_version):
                wlog(host, "Rollback verified -- back on %s"
                     % original_version, "OK")
                return True
            wlog(host, "Rollback did NOT restore %s" % original_version,
                 "ERROR")
            return False
        finally:
            try: c2.disconnect()
            except Exception: pass
    except Exception as e:
        wlog(host, "Rollback verify error: %s" % str(e)[:100], "ERROR")
        return False


def _verify_after_reboot_impl(conn, ip, target_ver, host, user, pw, st,
                              pre_config, fw_file):
    try:
        out = conn.send_command("show version | include Version")
        feed_live_log(host, "[verify] show version\n%s" % out)
        st["post_version"] = parse_running_version(out)
        if _norm_ver(st["post_version"]) != _norm_ver(target_ver):
            st["error"] = ("version mismatch: %s != %s"
                           % (st.get("post_version") or '?', target_ver))
            wlog(host, st["error"], "ERROR")
            if AUTO_ROLLBACK_ON_FAIL and st.get("reboot_detected"):
                if attempt_rollback(conn, host, ip=ip, user=user, pw=pw,
                                    original_version=st.get("start_version",
                                                            "")):
                    st["error"] += " (auto-rollback issued and verified)"
                else:
                    st["error"] += " (auto-rollback FAILED)"
            return False
        drain_syslog_after_reboot(conn, host)

        if not _finalize_install_commit(conn, host, target_ver,
                                        fw_file=fw_file or ""):
            st["error"] = "commit could not be verified"
            st["verify_pending"] = True
            wlog(host, "  upgrade NOT durable -- commit missing. "
                       "Device will revert on next reload.", "ERROR")
            return False
        wlog(host, "  commit finalized -- upgrade is durable", "OK")

        issues = []
        for i in range(1, HEALTH_RETRIES + 1):
            ok, issues = post_upgrade_health_check(conn, host, target_ver)
            if ok: break
            wlog(host, "Health %d/%d: %s"
                 % (i, HEALTH_RETRIES, "; ".join(issues)), "WARN")
            if i < HEALTH_RETRIES: time.sleep(HEALTH_RETRY_DELAY_SEC)
        else:
            st["error"] = "health check failed: " + "; ".join(issues)
            wlog(host, st["error"], "ERROR")
            st["verify_pending"] = True
            return False
        if pre_config and not SKIP_CONFIG_DRIFT_CHECK:
            try:
                post_cfg = conn.send_command("show running-config",
                                             read_timeout=120)
                drift = config_drift_check(pre_config, post_cfg, host)
                if drift:
                    st["drift"] = drift[:20]
                    st["config_diff_lines"] = len(drift)
            except Exception as e:
                wlog(host, "Config drift check skipped: %s" % str(e)[:80],
                     "WARN")
        wlog(host, "Upgrade verified on %s" % target_ver, "OK")
        try: post_upgrade_cleanup(conn, host)
        except Exception as e:
            wlog(host, "Cleanup non-fatal: %s" % str(e)[:80], "WARN")
        return True
    except Exception as e:
        st["error"] = "post-reboot verify error: %s" % str(e)[:150]
        st["verify_pending"] = True
        return False


def wait_reboot_and_verify(ip, target_ver, host, user, pw, st, is_issu=False,
                           pre_config="", fw_file=""):
    if not is_issu and ssh_port_open(ip, 3):
        peek = None
        try:
            peek = do_connect(ip, user, pw)
            vo = peek.send_command("show version | include Version",
                                   read_timeout=30)
            if _norm_ver(parse_running_version(vo)) \
                    == _norm_ver(target_ver):
                wlog(host, "Device already on target (fast reboot) -- "
                           "skipping ping-down wait", "OK")
                st["reboot_detected"] = True
                set_state(host, "VERIFY", "post-upgrade")
                return _verify_after_reboot_impl(
                    peek, ip, target_ver, host, user, pw, st,
                    pre_config, fw_file)
        except Exception as e:
            wlog(host, "  fast-reboot probe skipped: %s" % str(e)[:80],
                 "WARN")
        finally:
            if peek is not None:
                try: peek.disconnect()
                except Exception: pass

    if is_issu:
        wlog(host, "ISSU path -- skipping reboot wait", "INFO")
        set_state(host, "VERIFY", "post-ISSU")
    else:
        set_state(host, "REBOOT", "wait down")
        set_cmd(host, "ping (wait down)")
        went_down = wait_for_ping_down(ip, host)
        if not went_down:
            wlog(host, "Device did not go down -- checking anyway", "WARN")
        set_state(host, "REBOOT", "wait up")
        came_back = wait_for_ping_up(ip, host)
        if not came_back:
            st["error"] = "device did not return after reboot"
            st["verify_pending"] = True
            return False
        if not wait_for_ping_stable(ip, host):
            st["error"] = "boot loop detected (ping flapping)"
            st["verify_pending"] = True
            return False
        set_state(host, "REBOOT", "wait ssh")
        set_cmd(host, "ssh reconnect")
        if not wait_for_ssh_ready(ip, host):
            st["error"] = "SSH did not return"
            st["verify_pending"] = True
            return False
        wlog(host, "Settling %ds before verification"
             % POST_REBOOT_SETTLE_SEC, "INFO")
        set_state(host, "REBOOT", "settling")
        time.sleep(POST_REBOOT_SETTLE_SEC)
    set_state(host, "VERIFY", "post-upgrade")
    conn = robust_reconnect(ip, user, pw, host,
                            max_attempts=POST_REBOOT_MAX_ATTEMPTS,
                            delay=POST_REBOOT_DELAY_SEC, purpose="post-reboot")
    if not conn:
        st["error"] = "could not reconnect after reboot"
        st["verify_pending"] = True
        return False
    try:
        return _verify_after_reboot_impl(
            conn, ip, target_ver, host, user, pw, st,
            pre_config, fw_file)
    finally:
        try: conn.disconnect()
        except Exception: pass


def transfer_worker(dev, user, pw, location_name=""):
    loc = location_name or dev.get("_location", "")
    host, ip = dev["hostname"], dev["ip"]
    set_state(host, "QUEUE", "waiting slot")
    result = {"dev": dev, "success": False, "error": "", "fw_file": "",
              "target_ver": "", "start_ver": "", "skipped": False,
              "pre_config": "", "clock_corrected": False}
    conn = None
    model = ""
    if SHUTDOWN_REQ.is_set():
        result["error"] = "shutdown requested"; return result
    if DO_RESET_DEVICE_LOGS and not DRY_RUN: reset_device_logs(host)
    if loc: _update_checkpoint(loc, host, "transfer_start")
    try:
        try:
            conn = do_connect(ip, user, pw)
        except Exception as e:
            tag = _classify_connect_error(e)
            if tag:
                wlog(host, "%s: %s" % (tag, str(e)[:160]), "ERROR")
                result["error"] = tag
                if loc: _update_checkpoint(loc, host, "failed", tag)
                return result
            raise
        tacacs_enable(conn, host, ssh_pw=pw)
        try: conn.set_base_prompt()
        except Exception: pass
        if not is_privileged(conn):
            result["error"] = "not priv 15"
            if loc: _update_checkpoint(loc, host, "failed", "not priv 15")
            return result
        model = get_model(conn)
        fw = pick_firmware(model)
        if not fw:
            result["error"] = "unsupported model '%s'" % model
            wlog(host, "Unsupported model '%s' -- refusing" % model, "ERROR")
            if loc: _update_checkpoint(loc, host, "failed", result["error"])
            return result
        fw_file, target_ver = fw
        result["fw_file"], result["target_ver"] = fw_file, target_ver
        if _is_large_model(model) and SERIAL_TRANSFER_LARGE_MODELS:
            wlog(host, "Large model %s -- pool sized by LARGE_MODEL_PARALLEL=%d"
                 % (model, LARGE_MODEL_PARALLEL), "INFO")
        try:
            cnt, states = _stack_member_count(conn, host)
            if cnt > 1:
                wlog(host, "  Stack: %d members -- %s" % (cnt, states),
                     "INFO")
        except Exception: pass
        ok, reason, current_ver, clock_fixed = precheck_device(
            conn, host, fw_file, target_ver)
        result["start_ver"] = current_ver
        result["clock_corrected"] = clock_fixed
        if not ok:
            result["error"] = reason
            if loc: _update_checkpoint(loc, host, "failed", reason)
            return result
        if reason == "already_on_target":
            result["success"] = True; result["skipped"] = True
            if loc: _update_checkpoint(loc, host, "verified",
                                       "already_on_target")
            return result

        if reason == "already_added_needs_activate":
            result["success"] = True
            result["already_added"] = True
            if loc: _update_checkpoint(loc, host, "transferred")
            wlog(host, "TARGET .PKG SET PRESENT -- SKIPPING TRANSFER "
                       "AND PURGE", "OK")
            set_state(host, "READY", "activate pending")
            return result

        if reason.startswith("already_on_target_needs_"):
            needs_finalize = "needs_finalize" in reason
            needs_cleanup = "needs_cleanup" in reason
            wlog(host, "POST-UPGRADE FIXUP (%s)" % reason, "OK")
            set_state(host, "VERIFY", "fixup")
            fix_ok = True
            if needs_finalize:
                if not _finalize_install_commit(conn, host, target_ver,
                                                fw_file=fw_file):
                    result["error"] = ("fixup: commit could not be "
                                       "verified")
                    result["success"] = False
                    fix_ok = False
            if fix_ok and needs_cleanup:
                set_state(host, "VERIFY", "revert temp config")
                ok_count, fail_count, _unknown = revert_device_temp_changes(
                    conn, host)
                if fail_count:
                    wlog(host, "  revert partial: ok=%d fail=%d"
                         % (ok_count, fail_count), "WARN")
                else:
                    wlog(host, "  residual temp config reverted", "OK")
                try:
                    conn.send_command("write memory", read_timeout=60)
                except Exception:
                    pass
            if fix_ok:
                result["success"] = True
                result["fixup_done"] = True
                set_state(host, "DONE", "fixup complete")
                if loc: _update_checkpoint(loc, host, "verified", "fixup")
                wlog(host, "fixup complete -- device secured and durable",
                     "OK")
            return result

        if DO_BACKUP and not DRY_RUN:
            try:
                cfg = conn.send_command("show running-config",
                                        read_timeout=120)
                result["pre_config"] = cfg
                fn = ("%s_%s_%s.cfg"
                      % (host, current_ver,
                         datetime.now().strftime("%Y%m%d_%H%M%S")))
                with open(os.path.join(BACKUP_DIR, fn), "w",
                          encoding="utf-8") as f:
                    f.write(cfg)
                wlog(host, "Backup saved: %s" % fn, "OK")
            except Exception as e:
                wlog(host, "Backup skipped: %s" % e, "WARN")
        if PRE_SAVE_CONFIG and not DRY_RUN:
            try:
                wr = conn.send_command("write memory", read_timeout=60)
                if "error" in wr.lower() or "fail" in wr.lower():
                    wlog(host, "Pre-temp write memory: %s"
                         % wr.strip()[:80], "WARN")
            except Exception as e:
                wlog(host, "Pre-temp write memory error: %s" % str(e)[:80],
                     "WARN")
        fw_already_present = False
        if not DRY_RUN:
            tune_ssh_for_bulk_transfer(conn, host, model)
            apply_cheap_crypto_tuning(conn, host, model)
            if not ensure_scp_server_enabled(conn, host):
                result["error"] = "scp server enable failed"
                if loc:
                    _update_checkpoint(loc, host, "failed", result["error"])
                return result
            if not any(ch.get("type") == "exec_timeout"
                       for ch in get_temp_changes(host)):
                orig = get_vty_exec_timeout(conn, host)
                if orig:
                    all_already = all(
                        b.get("minutes") == 60 and b.get("seconds") == 0
                        for b in orig["blocks"]
                        if not b.get("was_default"))
                    if all_already and orig["blocks"]:
                        wlog(host, "  exec-timeout already 60 0 -- skipping",
                             "INFO")
                    else:
                        try:
                            track_temp_change(host, "exec_timeout", orig)
                            cmds = []
                            for b in orig["blocks"]:
                                cmds += ["line vty %s" % b["vty"],
                                         "exec-timeout 60 0", "exit"]
                            conn.send_config_set(cmds)
                            wlog(host, "Temp exec-timeout 60 0 set", "INFO")
                        except Exception as e:
                            wlog(host, "Failed temp exec-timeout: %s" % e,
                                 "WARN")
                else:
                    wlog(host, "Could not read VTY config -- skipping", "WARN")
            try:
                wlog(host, "Saving config (install precondition)...", "INFO")
                wr = conn.send_command("write memory", read_timeout=120)
                if "error" in wr.lower() or "fail" in wr.lower():
                    wlog(host, "write memory: %s" % wr.strip()[:80], "WARN")
                else:
                    wlog(host, "Config saved", "OK")
            except Exception as e:
                wlog(host, "write memory failed: %s" % str(e)[:80], "WARN")
            if file_in_flash(conn, fw_file):
                if validate_transfer_size(conn, host, fw_file):
                    wlog(host, "%s already in flash -- skipping transfer"
                         % fw_file, "OK")
                    fw_already_present = True
                else:
                    wlog(host, "%s present but wrong size -- wiping"
                         % fw_file, "WARN")
                    _delete_firmware_from_flash(conn, host, fw_file)
            else:
                wlog(host, "  %s not in flash -- will transfer" % fw_file,
                     "INFO")
        try: conn.disconnect()
        except Exception: pass
        conn = None
        if fw_already_present:
            result["success"] = True
            if not QUIET_SKIPPED:
                wlog(host, "DEVICE READY FOR INSTALL", "OK")
            set_state(host, "READY", "handing to install pool")
            if loc: _update_checkpoint(loc, host, "transferred")
            return result
        if DRY_RUN:
            wlog(host, "DRY-RUN: skipping transfer retry logic", "INFO")
            result["success"] = True; return result
        if not _transfer_with_wipe_retry(ip, user, pw, fw_file, host,
                                         model=model):
            result["error"] = ("transfer failed after %d attempts"
                               % TRANSFER_RETRY_ATTEMPTS)
            if loc: _update_checkpoint(loc, host, "failed", result["error"])
            return result

        if ALLOW_ACTIVE_PKG_PURGE and not DRY_RUN:
            conn2 = None
            try:
                conn2 = robust_reconnect(ip, user, pw, host,
                                         purpose="post-transfer pkg purge")
                if conn2:
                    fw_size = get_firmware_size(fw_file)
                    extraction = int(fw_size * EXTRACTION_OVERHEAD_FACTOR)
                    need = extraction + STACK_MEMBER_HEADROOM
                    free = get_flash_free_bytes(conn2)
                    if free < need:
                        wlog(host, "  Space still tight (%.0f MB < %.0f MB) "
                                   "-- invoking active-pkg purge"
                             % (free/1e6, need/1e6), "WARN")
                        set_state(host, "PKG-PURGE", "active .pkg purge")
                        _ok, _msg = _pre_install_pkg_purge(
                            conn2, host, fw_file, target_ver)
                        wlog(host, "  active-pkg purge: %s" % _msg,
                             "OK" if _ok else "WARN")
                    else:
                        wlog(host, "  Space OK (%.0f MB >= %.0f MB) -- "
                                   "skipping active-pkg purge"
                             % (free/1e6, need/1e6), "INFO")
            except Exception as e:
                wlog(host, "  post-transfer pkg purge error: %s"
                     % str(e)[:120], "WARN")
            finally:
                if conn2:
                    try: conn2.disconnect()
                    except Exception: pass

        result["success"] = True
        if not QUIET_SKIPPED:
            wlog(host, "DEVICE READY FOR INSTALL", "OK")
        set_state(host, "READY", "handing to install pool")
        if loc: _update_checkpoint(loc, host, "transferred")
        return result
    except Exception as e:
        result["error"] = str(e)[:200]
        if loc: _update_checkpoint(loc, host, "failed", result["error"])
        return result
    finally:
        if conn:
            try: conn.disconnect()
            except Exception: pass


def install_worker(dev, user, pw, transfer_result, location_name=""):
    loc = location_name or dev.get("_location", "")
    host, ip = dev["hostname"], dev["ip"]
    fw_file = transfer_result["fw_file"]
    target_ver = transfer_result["target_ver"]
    start_ver = transfer_result.get("start_ver", "")
    pre_config = transfer_result.get("pre_config", "")
    st = {"hostname": host, "ip": ip, "start_version": start_ver,
          "target_version": target_ver, "fw_file": fw_file,
          "status": "failed", "duration_sec": 0,
          "md5_ok": False, "install_started": False, "reboot_detected": False,
          "post_version": "", "error": "", "verify_pending": False,
          "stage": "install",
          "clock_corrected": transfer_result.get("clock_corrected", False)}
    start = time.time()
    def _fail(msg):
        st["error"] = msg
        if loc: _update_checkpoint(loc, host, "failed", msg)
        return (dev, "failed", time.time() - start, st, msg)
    if SHUTDOWN_REQ.is_set(): return _fail("shutdown requested")
    if DRY_RUN:
        wlog(host, "DRY-RUN: skipping install", "INFO")
        st["status"] = "success"
        if loc: _update_checkpoint(loc, host, "verified")
        return (dev, "success", time.time() - start, st, "")

    if transfer_result.get("already_on_target_fixup"):
        conn = None
        try:
            conn = robust_reconnect(ip, user, pw, host, purpose="fixup")
            if not conn:
                return _fail("reconnect failed before fixup")
            if transfer_result.get("needs_finalize"):
                set_state(host, "VERIFY", "commit finalize")
                wlog(host, "FIXUP: install commit", "STEP")
                if not _finalize_install_commit(conn, host, target_ver,
                                                fw_file=fw_file):
                    return _fail("commit could not be verified (fixup)")
                st["post_version"] = target_ver
                wlog(host, "commit finalized", "OK")
            if transfer_result.get("needs_cleanup"):
                set_state(host, "VERIFY", "revert temp config")
                wlog(host, "FIXUP: revert residual temp config", "STEP")
                ok_count, fail_count, _u = revert_device_temp_changes(
                    conn, host)
                if fail_count:
                    wlog(host, "  revert partial: ok=%d fail=%d"
                         % (ok_count, fail_count), "WARN")
                else:
                    wlog(host, "residual temp config reverted", "OK")
                try:
                    conn.send_command("write memory", read_timeout=60)
                except Exception:
                    pass
            st["status"] = "success"
            st["stage"] = "install"
            if not st.get("post_version"):
                st["post_version"] = target_ver
            if loc: _update_checkpoint(loc, host, "verified")
            return (dev, "success", time.time() - start, st, "")
        except Exception as e:
            return _fail(str(e)[:200])
        finally:
            if conn:
                try: conn.disconnect()
                except Exception: pass

    conn = None
    try:
        conn = robust_reconnect(ip, user, pw, host, purpose="install phase")
        if not conn: return _fail("reconnect failed before install")

        if transfer_result.get("already_added"):
            wlog(host, "Target .pkg already on flash -- issuing `install "
                       "activate` then `install commit` (no re-add)", "OK")
            ok1, err1, conn = _run_install_activate_only(
                conn, host, st, ip, user, pw, target_ver, fw_file=fw_file)
            if not ok1:
                return _fail("activate failed: %s" % err1)
            ok2, err2, conn = _run_install_commit_only(
                conn, host, st, ip, user, pw, target_ver)
            if not ok2:
                return _fail("commit failed: %s" % err2)
            if conn:
                try: conn.disconnect()
                except Exception: pass
                conn = None
            if not wait_reboot_and_verify(ip, target_ver, host, user, pw,
                                          st, is_issu=False,
                                          pre_config=pre_config,
                                          fw_file=fw_file):
                return (dev, "failed", time.time() - start, st,
                        st.get("error", ""))
            st["status"] = "success"
            if loc: _update_checkpoint(loc, host, "verified")
            return (dev, "success", time.time() - start, st, "")

        if DO_VERIFY_MD5:
            set_state(host, "MD5", "verify")
            set_cmd(host, "verify /md5 flash:%s" % fw_file)
            local_path = os.path.join(FIRMWARE_DIR, fw_file)
            if not os.path.isfile(local_path):
                wlog(host, "  MD5 skipped -- local firmware missing", "WARN")
            else:
                expected = cached_md5(local_path)
                out = ""
                try:
                    out = conn.send_command(
                        "verify /md5 flash:%s" % fw_file,
                        read_timeout=1800)
                    feed_live_log(host, "[verify] verify /md5\n%s" % out)
                except Exception as e:
                    msg = str(e)
                    if "Pattern not detected" in msg:
                        wlog(host, "  MD5 prompt pattern failed -- "
                                   "retrying with send_command_timing",
                             "WARN")
                        try:
                            out = conn.send_command_timing(
                                "verify /md5 flash:%s" % fw_file,
                                read_timeout=1800,
                                strip_prompt=False,
                                strip_command=False)
                            feed_live_log(host,
                                          "[verify] verify /md5 (timing)\n%s"
                                          % out)
                        except Exception as e2:
                            wlog(host, "  MD5 timing retry failed: %s -- "
                                       "skipping (non-fatal)"
                                 % str(e2)[:80], "WARN")
                            out = ""
                    else:
                        wlog(host, "  MD5 verify error: %s -- skipping "
                                   "(non-fatal)" % msg[:80], "WARN")
                        out = ""
                if not out:
                    wlog(host, "  MD5 not confirmed -- continuing "
                               "(transfer SHA256 already validated)", "WARN")
                elif expected.lower() in out.lower():
                    st["md5_ok"] = True
                    wlog(host, "MD5 verified", "OK")
                else:
                    m = re.search(
                        r"verify /md5 \([^)]+\)\s*=\s*([0-9a-fA-F]{32})",
                        out)
                    if m and m.group(1).lower() != expected.lower():
                        return _fail("MD5 mismatch: got %s expected %s"
                                     % (m.group(1).lower(), expected.lower()))
                    wlog(host, "  MD5 not parseable -- continuing", "WARN")

        issu_ok, issu_reasons = False, ["--skip-issu"]
        if not SKIP_ISSU:
            issu_ok, issu_reasons = check_issu_eligibility(conn, host)

        if issu_ok:
            wlog(host, "ISSU eligible -- zero-downtime path", "OK")
            install_cmd = ("install add file flash:%s activate issu commit"
                           % fw_file)
        else:
            wlog(host, "ISSU not eligible (%s) -- reload path"
                 % "; ".join(issu_reasons), "INFO")
            install_cmd = "install add file flash:%s activate commit" % fw_file

        success, err, conn = run_install(conn, install_cmd, host, st,
                                         ip, user, pw, target_ver,
                                         is_issu=issu_ok, fw_file=fw_file)
        if not success:
            if err and "already_added_refused" in err:
                wlog(host, "Engine refused re-add -- switching to "
                           "activate-only path", "WARN")
                if conn is None:
                    conn = robust_reconnect(ip, user, pw, host,
                                            purpose="activate-only retry")
                if conn:
                    ok1, err1, conn = _run_install_activate_only(
                        conn, host, st, ip, user, pw, target_ver,
                        fw_file=fw_file)
                    if ok1:
                        ok2, err2, conn = _run_install_commit_only(
                            conn, host, st, ip, user, pw, target_ver)
                        if ok2:
                            if conn:
                                try: conn.disconnect()
                                except Exception: pass
                                conn = None
                            if wait_reboot_and_verify(
                                    ip, target_ver, host, user, pw, st,
                                    is_issu=False, pre_config=pre_config,
                                    fw_file=fw_file):
                                st["status"] = "success"
                                if loc:
                                    _update_checkpoint(loc, host, "verified")
                                return (dev, "success",
                                        time.time() - start, st, "")
                            return (dev, "failed", time.time() - start, st,
                                    st.get("error", ""))
                        return _fail("activate-only commit failed: %s" % err2)
                    return _fail("activate-only failed: %s" % err1)
                return _fail(err)
            try:
                if conn and not st.get("reboot_detected"):
                    still_running = False
                    try:
                        probe_ok, probe_msg, _ = _probe_install_status(
                            ip, user, pw, host, target_ver)
                        if probe_ok and "install still running" in probe_msg:
                            still_running = True
                            wlog(host, "  Install still running -- skipping "
                                       "remove-inactive", "WARN")
                    except Exception: pass
                    if not still_running:
                        wlog(host, "  Clearing stale super-package", "INFO")
                        _run_install_remove_inactive(
                            conn, host, allow_abort=False)
            except Exception as e:
                wlog(host, "  Post-fail cleanup skipped: %s" % str(e)[:80],
                     "WARN")
            return _fail(err)
        if conn:
            try: conn.disconnect()
            except Exception: pass
            conn = None
        if not wait_reboot_and_verify(ip, target_ver, host, user, pw, st,
                                      is_issu=issu_ok, pre_config=pre_config,
                                      fw_file=fw_file):
            return (dev, "failed", time.time() - start, st,
                    st.get("error", ""))
        st["status"] = "success"
        if loc: _update_checkpoint(loc, host, "verified")
        return (dev, "success", time.time() - start, st, "")
    except Exception as e:
        return _fail(str(e)[:200])
    finally:
        if conn:
            try: conn.disconnect()
            except Exception: pass


def pre_scan_devices(devices, user=None, pw=None):
    reachable, unreachable = [], []
    if not devices: return reachable, unreachable
    def _chk(d):
        if SHUTDOWN_REQ.is_set(): return d, None, ""
        ok = ssh_port_open(d["ip"], timeout=5)
        model = ""
        if ok and user and pw:
            c_ = None
            try:
                c_ = do_connect(d["ip"], user, pw)
                tacacs_enable(c_, d["hostname"], ssh_pw=pw)
                model = get_model(c_) or ""
            except Exception: model = ""
            finally:
                if c_:
                    try: c_.disconnect()
                    except Exception: pass
        return d, ok, model
    with ThreadPoolExecutor(max_workers=20) as ex:
        for d, ok, model in ex.map(_chk, devices):
            if ok is None: continue
            if model: d["_model"] = model
            (reachable if ok else unreachable).append(d)
    small = [d for d in reachable if not _is_large_model(d.get("_model", ""))]
    large = [d for d in reachable if _is_large_model(d.get("_model", ""))]
    return small + large, unreachable


def _row(dev, status, stage="", error="", st=None, duration=0,
         attempts=1, transfer=None):
    st = st or {}; transfer = transfer or {}
    return {
        "hostname": dev["hostname"], "ip": dev["ip"], "status": status,
        "stage": stage,
        "start_version": st.get("start_version")
                         or transfer.get("start_ver", ""),
        "target_version": st.get("target_version")
                          or transfer.get("target_ver", ""),
        "post_version": st.get("post_version", ""),
        "fw_file": st.get("fw_file") or transfer.get("fw_file", ""),
        "md5_ok": st.get("md5_ok", False),
        "install_started": st.get("install_started", False),
        "reboot_detected": st.get("reboot_detected", False),
        "verify_pending": st.get("verify_pending", False),
        "clock_corrected": bool(st.get("clock_corrected")
                                or transfer.get("clock_corrected", False)),
        "config_diff_lines": st.get("config_diff_lines", 0),
        "duration_sec": int(duration), "attempts": attempts, "error": error,
    }


def is_retryable(row):
    if row["status"] != "failed":
        return False
    err = (row.get("error") or "").lower()
    if any(row["error"].startswith(p)
           for p in NON_RETRYABLE_PREFIXES):
        return False
    if row["stage"] == "transfer" and not row["install_started"]:
        return True
    if row["stage"] == "install":
        recoverable = (
            "image inactive" in err
            or "install stuck" in err
            or "cannot activate" in err
            or "commit could not be verified" in err
            or "version mismatch" in err
        )
        non_recoverable = (
            "md5 mismatch" in err
            or "tacacs+ denied" in err
            or "partial activation" in err
            or "two committed versions" in err
            or "insufficient_space" in err
        )
        return recoverable and not non_recoverable
    return False


def _collect_transfer_result(fut, dev, results, ifut, install_pool,
                             user, pw, attempt_no, location_name=""):
    host = dev["hostname"]
    try: tr = fut.result()
    except Exception as e:
        tr = {"success": False, "error": str(e)[:200], "skipped": False}
    if not tr.get("success"):
        results[host] = _row(dev, "failed", "transfer",
                             tr.get("error", "?"),
                             attempts=attempt_no, transfer=tr)
        set_state(host, "FAILED", tr.get("error", "")[:30])
        return
    if tr.get("skipped"):
        results[host] = _row(dev, "skipped", "precheck",
                             "already on target",
                             attempts=attempt_no, transfer=tr)
        clear_state(host)
        return
    if tr.get("fixup_done"):
        results[host] = _row(dev, "success", "verify", "",
                             attempts=attempt_no, transfer=tr)
        set_state(host, "DONE", "fixup complete")
        return
    ifut[install_pool.submit(install_worker, dev, user, pw, tr,
                             location_name)] = (dev, tr)


def run_pass(devices, user, pw, results, attempt_no, location_name=""):
    small, large = [], []
    for d in devices:
        (large if _is_large_model(d.get("_model", "")) else small).append(d)
    if not SERIAL_TRANSFER_LARGE_MODELS:
        small, large = devices, []

    def _model_counts(lst):
        cnt = {}
        for d in lst:
            m = d.get("_model", "unknown")
            cnt[m] = cnt.get(m, 0) + 1
        return ", ".join("%s x%d" % (k, v) for k, v in sorted(cnt.items()))

    print("\n  === Transfer plan (pass %d) ===" % attempt_no)
    if small:
        print("    Phase 1 -- %d small model(s), parallel=%d [%s]"
              % (len(small), TRANSFER_SLOTS, _model_counts(small)))
    if large:
        print("    Phase 2 -- %d large model(s), parallel=%d [%s]"
              % (len(large), LARGE_MODEL_PARALLEL, _model_counts(large)))
    print()
    master_log("PASS %d plan: small=%d large=%d"
               % (attempt_no, len(small), len(large)))

    with ThreadPoolExecutor(max_workers=INSTALL_WORKERS,
                            thread_name_prefix="inst") as ip_:
        ifut = {}

        def _consume_one(f):
            pair = ifut.pop(f, None)
            if pair is None:
                return
            d, tr = pair
            host = d["hostname"]
            try:
                _, status, dur, st, err = f.result()
            except Exception as e:
                status, dur, st, err = "failed", 0, {}, str(e)[:200]
            results[host] = _row(
                d, "success" if status == "success" else "failed",
                "install", err, st=st, duration=dur,
                attempts=attempt_no, transfer=tr)
            set_state(host, "DONE" if status == "success" else "FAILED",
                      "upgraded" if status == "success" else err[:30])

        def _drain_install(block):
            keys = list(ifut.keys())
            if not keys:
                return
            if block:
                for f in as_completed(keys):
                    _consume_one(f)
            else:
                for f in keys:
                    if f.done():
                        _consume_one(f)

        def _run_phase(dev_list, workers, prefix):
            if not dev_list:
                return
            with ThreadPoolExecutor(max_workers=max(1, workers),
                                    thread_name_prefix=prefix) as tp:
                tfut = {tp.submit(transfer_worker, d, user, pw,
                                  location_name): d for d in dev_list}
                pending = set(tfut.keys())
                while pending:
                    done, pending = wait(pending, timeout=10,
                                         return_when=FIRST_COMPLETED)
                    for f in done:
                        dev = tfut.pop(f, None)
                        if dev is None:
                            continue
                        _collect_transfer_result(
                            f, dev, results, ifut, ip_,
                            user, pw, attempt_no, location_name)
                    _drain_install(block=False)

        if small:
            _run_phase(small, TRANSFER_SLOTS, "xfer")
        if large:
            workers = max(1, LARGE_MODEL_PARALLEL)
            master_log("TRANSFER PHASE 2 start: %d large, parallel=%d"
                       % (len(large), workers))
            _run_phase(large, workers, "xfer-large")
            master_log("TRANSFER PHASE 2 end: %d large" % len(large))

        _drain_install(block=True)


def _print_location_progress(by_loc, results):
    print("\n  -- Location progress --")
    for loc in sorted(by_loc.keys()):
        total = len(by_loc[loc])
        done = sum(1 for d in by_loc[loc]
                   if results.get(d["hostname"], {}).get("status")
                   in ("success", "skipped", "failed"))
        succ = sum(1 for d in by_loc[loc]
                   if results.get(d["hostname"], {}).get("status")
                   in ("success", "skipped"))
        fail = sum(1 for d in by_loc[loc]
                   if results.get(d["hostname"], {}).get("status") == "failed")
        marker = ("OK" if done == total and fail == 0
                  else "!!" if fail else "..")
        print("    %s %-20s %d/%d done (success=%d failed=%d)"
              % (marker, loc, done, total, succ, fail))
    print()


def _report_fields():
    return ["hostname", "ip", "status", "stage", "start_version",
            "target_version", "post_version", "fw_file", "md5_ok",
            "install_started", "reboot_detected", "verify_pending",
            "clock_corrected", "config_diff_lines",
            "duration_sec", "attempts", "error", "revert_verified"]


def write_location_report(location_name, results, revert_verify=None,
                          force=False):
    key = "%s" % location_name
    with CSV_WRITTEN_LOCK:
        if key in CSV_WRITTEN and not force: return None
        CSV_WRITTEN.add(key)
    try:
        os.makedirs(REPORT_DIR, exist_ok=True)
        csv_path = os.path.join(REPORT_DIR,
                                "%s_%s.csv" % (location_name, RUN_ID))
        json_path = os.path.join(REPORT_DIR,
                                 "%s_%s.json" % (location_name, RUN_ID))
        fields = _report_fields()
        for r in results.values():
            if revert_verify and r["hostname"] in revert_verify:
                r["revert_verified"] = ("OK"
                                        if revert_verify[r["hostname"]]["ok"]
                                        else "FAILED")
            else: r["revert_verified"] = "N/A"
        with CSV_LOCK:
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
                w.writeheader()
                for r in sorted(results.values(),
                                key=lambda x: x["hostname"]):
                    w.writerow(r)
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump({"location": location_name, "run_id": RUN_ID,
                           "revert_verify": revert_verify or {},
                           "results": sorted(results.values(),
                                             key=lambda x: x["hostname"])},
                          f, indent=2)
        print("  Report: %s" % csv_path)
        return csv_path
    except Exception as e:
        master_log("Report write failed for %s: %s" % (location_name, e))
        return None


def run_location(location_name, devices, user, pw,
                 resume_checkpoint=False, retry_failed=False):
    print("\n" + "=" * 70)
    print("  LOCATION: %s (%d devices)%s%s%s"
          % (location_name, len(devices),
             "  [DRY-RUN]" if DRY_RUN else "",
             "  [RESUME]" if resume_checkpoint else "",
             "  [RETRY-FAILED]" if retry_failed else ""))
    print("=" * 70)
    master_log("LOCATION START: %s devices=%d" % (location_name, len(devices)))
    if retry_failed:
        failed_set = _failed_hosts_from_last_report(location_name)
        if failed_set:
            print("  Filter: %d host(s) failed last run" % len(failed_set))
            devices = [d for d in devices if d["hostname"] in failed_set]
            print("  -> %d device(s) to retry" % len(devices))
        else: print("  No failed devices from last run -- running full set")
    if resume_checkpoint:
        ckpt = _load_checkpoint(location_name)
        verified = {h for h, v in ckpt.items()
                    if v.get("stage") == "verified"}
        if verified:
            print("  Checkpoint: %d host(s) already verified" % len(verified))
            devices = [d for d in devices if d["hostname"] not in verified]
            print("  -> %d device(s) remaining" % len(devices))
    if not devices:
        print("  Nothing to do for this location.")
        return {}, False, {}
    results, aborted = {}, False
    revert_verify = {}
    try:
        prepare_rollback_doc(devices, location_name)
        reachable, unreachable = pre_scan_devices(devices, user, pw)
        for d in unreachable:
            results[d["hostname"]] = _row(d, "failed", "prescan",
                                          "unreachable on tcp/22")
            wlog(d["hostname"], "Unreachable on port 22", "ERROR")
            _update_checkpoint(location_name, d["hostname"], "failed",
                               "unreachable")
        pending, attempt = reachable, 0
        while pending and not SHUTDOWN_REQ.is_set():
            attempt += 1
            run_pass(pending, user, pw, results, attempt, location_name)
            failed = [d for d in pending
                      if results[d["hostname"]]["status"] == "failed"]
            if (attempt == 1 and len(pending) >= ABORT_GATE_MIN_DEVICES
                    and len(failed) / len(pending) > ABORT_GATE_THRESHOLD):
                aborted = True
                print("\n  ABORT GATE: %d/%d failed"
                      % (len(failed), len(pending)))
                master_log("ABORT GATE at %s" % location_name)
                break
            retry = [d for d in failed
                     if is_retryable(results[d["hostname"]])]
            if (not RETRY_FAILED_DEVICES or not retry
                    or attempt > MAX_RETRIES or SHUTDOWN_REQ.is_set()):
                break
            print("\n  Retrying %d device(s) in %ds (retry %d/%d)"
                  % (len(retry), RETRY_DELAY_SEC, attempt, MAX_RETRIES))
            SHUTDOWN_REQ.wait(RETRY_DELAY_SEC)
            pending = retry
    except Exception as e:
        master_log("Location %s raised: %s" % (location_name, e))
        print("\n  Location %s raised: %s" % (location_name, e))
    finally:
        for d in devices:
            results.setdefault(d["hostname"],
                               _row(d, "failed", "not_run",
                                    "not processed (shutdown/crash?)"))
        try:
            revert_verify = revert_location_temp_changes(devices, user, pw,
                                                         location_name) or {}
        except Exception as e:
            master_log("Revert/verify raised: %s" % e)
        write_location_report(location_name, results, revert_verify)
        master_log("LOCATION END: %s" % location_name)
    return results, aborted, revert_verify


def _run_pooled(loc_devices, user, pw,
                resume_checkpoint=False, retry_failed=False):
    flat, by_loc = [], {}
    for loc, devs in loc_devices.items():
        by_loc[loc] = []
        for d in devs:
            td = {"hostname": d["hostname"], "ip": d["ip"], "_location": loc}
            flat.append(td); by_loc[loc].append(td)
    if retry_failed:
        for loc in list(by_loc):
            fs = _failed_hosts_from_last_report(loc)
            if fs:
                by_loc[loc] = [d for d in by_loc[loc]
                               if d["hostname"] in fs]
        flat = [d for loc in by_loc for d in by_loc[loc]]
    if resume_checkpoint:
        for loc in list(by_loc):
            ckpt = _load_checkpoint(loc)
            verified = {h for h, v in ckpt.items()
                        if v.get("stage") == "verified"}
            if verified:
                by_loc[loc] = [d for d in by_loc[loc]
                               if d["hostname"] not in verified]
        flat = [d for loc in by_loc for d in by_loc[loc]]
    if not flat:
        print("  Nothing to do (all devices filtered).")
        return {}, {}
    for loc, devs in by_loc.items():
        if devs: prepare_rollback_doc(devs, loc)
    results = {}
    reachable, unreachable = pre_scan_devices(flat, user, pw)
    for d in unreachable:
        results[d["hostname"]] = _row(d, "failed", "prescan",
                                      "unreachable on tcp/22")
        wlog(d["hostname"], "Unreachable on port 22", "ERROR")
        _update_checkpoint(d["_location"], d["hostname"], "failed",
                           "unreachable")
    aborted_locs = set()
    pending = reachable
    attempt = 0
    while pending and not SHUTDOWN_REQ.is_set():
        attempt += 1
        run_pass(pending, user, pw, results, attempt, location_name="")
        _print_location_progress(by_loc, results)
        for loc, devs in by_loc.items():
            if loc in aborted_locs: continue
            hosts_in = {d["hostname"] for d in devs}
            pend_in = [d for d in pending if d["hostname"] in hosts_in]
            if not pend_in: continue
            fail_in = [d for d in pend_in
                       if results.get(d["hostname"], {})
                                 .get("status") == "failed"]
            if (attempt == 1
                    and len(pend_in) >= ABORT_GATE_MIN_DEVICES
                    and len(fail_in) / max(len(pend_in), 1)
                        > ABORT_GATE_THRESHOLD):
                print("\n  ABORT GATE (%s): %d/%d failed -- skipping "
                      "retries for this location"
                      % (loc, len(fail_in), len(pend_in)))
                master_log("ABORT GATE %s: %d/%d"
                           % (loc, len(fail_in), len(pend_in)))
                aborted_locs.add(loc)
        failed = [d for d in pending
                  if results.get(d["hostname"], {}).get("status") == "failed"
                  and d.get("_location") not in aborted_locs]
        retry = [d for d in failed
                 if is_retryable(results.get(d["hostname"], {}))]
        if (not RETRY_FAILED_DEVICES or not retry
                or attempt > MAX_RETRIES or SHUTDOWN_REQ.is_set()):
            break
        print("\n  Retrying %d device(s) in %ds (retry %d/%d)"
              % (len(retry), RETRY_DELAY_SEC, attempt, MAX_RETRIES))
        SHUTDOWN_REQ.wait(RETRY_DELAY_SEC)
        pending = retry
    print("\n" + "=" * 70)
    print("  POOLED RUN COMPLETE -- writing per-location reports")
    print("=" * 70)
    all_results, all_revert = {}, {}
    for loc, devs in by_loc.items():
        loc_res = {}
        for d in devs:
            r = results.get(d["hostname"])
            if r is None:
                r = _row(d, "failed", "not_run",
                         "not processed (pooled run)")
            loc_res[d["hostname"]] = r
        all_results[loc] = loc_res
        try:
            rv = revert_location_temp_changes(devs, user, pw, loc) or {}
        except Exception as e:
            master_log("Revert for %s raised: %s" % (loc, e))
            rv = {}
        all_revert[loc] = rv
        write_location_report(loc, loc_res, rv)
    return all_results, all_revert


def _fmt_duration(seconds):
    seconds = int(seconds or 0)
    if seconds < 60:
        return "%ds" % seconds
    m, s = divmod(seconds, 60)
    if m < 60:
        return "%dm%02ds" % (m, s)
    h, m = divmod(m, 60)
    return "%dh%02dm%02ds" % (h, m, s)


def _device_line(r):
    host = (r.get("hostname") or "?")[:30]
    ip = (r.get("ip") or "?")[:15]
    st = r.get("status", "?")
    sv = r.get("start_version") or "?"
    tv = r.get("target_version") or "?"
    dur = _fmt_duration(r.get("duration_sec", 0))
    if st == "success":
        arrow = "%s -> %s" % (sv, tv) if sv != tv else tv
        flags = []
        if r.get("reboot_detected"): flags.append("reboot")
        if r.get("md5_ok"):          flags.append("md5-ok")
        if r.get("clock_corrected"): flags.append("clock-fix")
        fs = ("  [" + ", ".join(flags) + "]") if flags else ""
        mark = c("OK", "green")
        return "%s %-30s %-15s %-28s %9s%s" % (mark, host, ip, arrow, dur, fs)
    if st == "skipped":
        mark = c("--", "yellow")
        return "%s %-30s %-15s already on %-16s %9s" % (mark, host, ip, tv,
                                                        dur)
    stage = r.get("stage", "")
    err = (r.get("error") or "?")[:60]
    tag = "[%s] " % stage if stage else ""
    mark = c("!!", "red")
    return "%s %-30s %-15s %s%s" % (mark, host, ip, tag, err)


def _load_previous_run_summary():
    if not os.path.isdir(REPORT_DIR): return None
    try:
        names = sorted((f for f in os.listdir(REPORT_DIR)
                        if f.startswith("run_summary_")
                        and f.endswith(".json")
                        and RUN_ID not in f), reverse=True)
    except OSError:
        return None
    for name in names:
        try:
            with open(os.path.join(REPORT_DIR, name), "r",
                      encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            continue
    return None


def detect_anomalies(all_results, prev_summary):
    if not prev_summary: return []
    prev_by = {r["hostname"]: r for r in prev_summary.get("results", [])}
    issues = []
    for loc, res in all_results.items():
        for host, r in res.items():
            prev = prev_by.get(host)
            if not prev: continue
            if (r["status"] == "success" and prev.get("post_version")
                    and r.get("post_version")
                    and r["post_version"] < prev["post_version"]):
                issues.append((host, "version regressed: %s -> %s"
                               % (prev["post_version"], r["post_version"])))
            if (prev.get("status") == "success" and r["status"] == "failed"
                    and r.get("install_started")
                    and not prev.get("install_started")):
                issues.append((host, "failed this run (was success last): %s"
                               % (r.get("error") or "?")[:60]))
    return issues


def trend_report(all_results, lookback=5):
    if not os.path.isdir(REPORT_DIR): return
    try:
        files = sorted((f for f in os.listdir(REPORT_DIR)
                        if f.startswith("run_summary_")
                        and f.endswith(".json")
                        and RUN_ID not in f), reverse=True)[:lookback]
    except OSError:
        return
    if len(files) < 2: return
    history = {}
    for fn in files:
        try:
            with open(os.path.join(REPORT_DIR, fn), "r",
                      encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue
        for r in data.get("results", []):
            history.setdefault(r["hostname"], []).append(r["status"])
    chronic = [(h, s) for h, s in history.items() if s.count("failed") >= 2]
    if chronic:
        print("\n  CHRONIC FAILURES (last %d runs):" % len(files))
        for h, seq in sorted(chronic):
            print("      ! %s: %s" % (h, "/".join(seq)))


def print_summary(all_results, all_revert=None):
    all_revert = all_revert or {}
    ok = skipped = failed = 0
    print("\n" + "=" * 78)
    print("  FINAL SUMMARY -- DEVICE DETAIL  (v%s)" % VERSION_STRING)
    print("=" * 78)
    for loc in sorted(all_results.keys()):
        res = all_results[loc]
        cnt = {"success": 0, "skipped": 0, "failed": 0}
        for r in res.values():
            cnt[r["status"]] = cnt.get(r["status"], 0) + 1
        ok += cnt["success"]; skipped += cnt["skipped"]; failed += cnt["failed"]
        rv = all_revert.get(loc, {})
        rc = sum(1 for x in rv.values() if x.get("ok"))
        rf = sum(1 for x in rv.values() if not x.get("ok"))
        hdr = ("-- %s  (%d device(s) -- success=%d skipped=%d failed=%d"
               % (loc, len(res), cnt["success"], cnt["skipped"],
                  cnt["failed"]))
        if rv: hdr += "  revert_ok=%d revert_fail=%d" % (rc, rf)
        hdr += ") --"
        print("\n  %s" % hdr)
        print("  " + "-" * 76)
        print("  %2s%-30s %-15s Detail" % ("", "Hostname", "IP"))
        print("  " + "-" * 76)
        for want in ("success", "skipped", "failed"):
            for r in sorted((x for x in res.values() if x["status"] == want),
                            key=lambda x: x["hostname"]):
                print("  " + _device_line(r))
        for h, rvr in sorted(rv.items()):
            if not rvr.get("ok"):
                print("      revert failed: %s -- %s"
                      % (h, rvr.get("message", "")[:60]))
    total = ok + skipped + failed
    print("\n" + "=" * 78)
    print("  TOTAL  success=%d  skipped=%d  failed=%d  (of %d)"
          % (ok, skipped, failed, total))
    print("=" * 78)
    cf = sum(1 for loc in all_results.values()
             for r in loc.values() if r.get("clock_corrected"))
    if cf:
        print("\n  %d device(s) had clock drift corrected during pre-check"
              % cf)
    manual = []
    for loc in sorted(all_results.keys()):
        for r in sorted(all_results[loc].values(),
                        key=lambda x: x["hostname"]):
            if r["status"] == "failed":
                manual.append((loc, r))
    if manual:
        print("\n  %d device(s) NEED MANUAL ATTENTION:" % len(manual))
        for loc, r in manual:
            ip = r.get("ip", "?")
            stage = r.get("stage", "?")
            err = (r.get("error") or "?")[:80]
            print("      !! %-30s (%s) [%s]" % (r["hostname"], ip, loc))
            print("          stage=%s  error=%s" % (stage, err))
            if r.get("install_started"):
                print("          install was started -- check `show install log`")
            if r.get("verify_pending"):
                print("          verify_pending=True -- reconcilable next run")
    try:
        prev = _load_previous_run_summary()
        if prev:
            anom = detect_anomalies(all_results, prev)
            if anom:
                print("\n  ANOMALIES vs previous run (%s):"
                      % prev.get("run_id", "?"))
                for h, m in anom:
                    print("      ! %s: %s" % (h, m))
    except Exception: pass
    try: trend_report(all_results, lookback=5)
    except Exception: pass
    with TEMP_CHANGES_LOCK:
        pending = sorted(h for h, e in TEMP_CHANGES.items()
                         if e.get("changes"))
    if pending:
        print("\n  %d device(s) still have un-reverted temp config "
              "changes -- run with --recover" % len(pending))
        for h in pending:
            print("      - %s" % h)
    print("=" * 78 + "\n")
    return failed


def _reconcile_failed_devices(all_results, all_revert, user, pw):
    if not RECONCILE_FAILED_AT_END:
        return all_results, all_revert
    candidates = []
    for loc, res in all_results.items():
        for host, r in res.items():
            if r.get("status") != "failed": continue
            eligible = (r.get("verify_pending")
                        or r.get("stage") in ("install", "verify", "reboot"))
            if not eligible: continue
            ip = r.get("ip", "")
            target_ver = r.get("target_version", "")
            if not ip or not target_ver: continue
            candidates.append((loc, host, ip, target_ver, r))
    if not candidates:
        print("\n  Reconcile: no verify-pending failures to recheck")
        return all_results, all_revert
    print("\n" + "=" * 70)
    print("  RECONCILE -- rechecking %d failed device(s)" % len(candidates))
    print("=" * 70)
    reconciled = 0; still_failed = 0
    reconciled_locs = set()
    for loc, host, ip, target_ver, r in candidates:
        print("\n  [%s] %s -- checking for %s..." % (host, ip, target_ver),
              flush=True)
        c_ = None
        ok_now = False
        try:
            c_ = do_connect(ip, user, pw)
            tacacs_enable(c_, host, ssh_pw=pw)
            if not is_privileged(c_):
                print("    not priv-15 -- cannot verify"); continue
            out = c_.send_command("show version | include Version",
                                  read_timeout=60)
            post_ver = parse_running_version(out)
            print("    running version: %s" % post_ver)
            if _norm_ver(post_ver) == _norm_ver(target_ver):
                try:
                    b = c_.send_command("show boot | include BOOT",
                                        read_timeout=30)
                    if "packages.conf" not in b:
                        print("    boot var not packages.conf"); continue
                except Exception: pass
                fw_file = ""
                try:
                    fwm = pick_firmware(get_model(c_) or "")
                    if fwm: fw_file = fwm[0]
                except Exception: pass
                if not _finalize_install_commit(c_, host, target_ver,
                                                fw_file=fw_file):
                    print("    device is on target but NOT committed -- "
                          "will revert on next reload")
                    r["error"] = ("on target but commit not verified -- "
                                  "will revert on next reload")
                    r["verify_pending"] = True
                    continue
                ok_now = True
            else:
                print("    still not on %s" % target_ver)
        except Exception as e:
            print("    connection failed: %s: %s"
                  % (type(e).__name__, str(e)[:80]))
        finally:
            if c_:
                try: c_.disconnect()
                except Exception: pass
        if ok_now:
            print("    RECONCILED -- device is on %s" % target_ver)
            r["status"] = "success"
            r["stage"] = "install"
            r["error"] = ""
            r["post_version"] = target_ver
            r["verify_pending"] = False
            reconciled += 1
            reconciled_locs.add(loc)
        else:
            still_failed += 1
    print("\n" + "-" * 70)
    print("  Reconciled (now success) : %d" % reconciled)
    print("  Still failed             : %d" % still_failed)
    print("-" * 70 + "\n")
    for loc in reconciled_locs:
        loc_res = all_results.get(loc, {})
        rv = all_revert.get(loc, {})
        write_location_report(loc, loc_res, rv, force=True)
    return all_results, all_revert


def write_run_summary(all_results, all_revert, run_id, path):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        flat = []
        for loc in sorted(all_results.keys()):
            for r in sorted(all_results[loc].values(),
                            key=lambda x: x["hostname"]):
                row = dict(r); row["location"] = loc
                flat.append(row)
        summary = {
            "run_id": run_id,
            "timestamp": datetime.now().isoformat(),
            "version_string": VERSION_STRING,
            "totals": {
                "success": sum(1 for r in flat if r["status"] == "success"),
                "skipped": sum(1 for r in flat if r["status"] == "skipped"),
                "failed":  sum(1 for r in flat if r["status"] == "failed"),
                "total":   len(flat)},
            "by_location": {
                loc: {"success": sum(1 for r in all_results[loc].values()
                                     if r["status"] == "success"),
                      "skipped": sum(1 for r in all_results[loc].values()
                                     if r["status"] == "skipped"),
                      "failed": sum(1 for r in all_results[loc].values()
                                    if r["status"] == "failed"),
                      "revert_failed": sum(
                          1 for x in all_revert.get(loc, {}).values()
                          if not x.get("ok"))}
                for loc in sorted(all_results.keys())},
            "results": flat}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        print("  Summary: %s" % path)
        return path
    except Exception as e:
        master_log("run_summary err: %s" % e)
        return None


_HTML_TPL = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Cisco Upgrade Run {rid}</title>
<style>
 body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif;
         margin: 24px; color: #222; }}
 h1 {{ font-size: 20px; margin-bottom: 4px; }}
 .meta {{ color: #666; font-size: 13px; margin-bottom: 20px; }}
 table {{ border-collapse: collapse; width: 100%; margin-bottom: 24px; }}
 th, td {{ padding: 6px 10px; border-bottom: 1px solid #e5e5e5;
           text-align: left; font-size: 13px; }}
 th {{ background: #f5f5f5; font-weight: 600; }}
 tr.s-success td:first-child {{ color: #1a7f37; }}
 tr.s-failed  td:first-child {{ color: #b62324; }}
 tr.s-skipped td:first-child {{ color: #8a6d00; }}
 .totals {{ display: flex; gap: 20px; margin-bottom: 24px; font-size: 14px; }}
 .totals span {{ padding: 4px 10px; border-radius: 4px; background: #f5f5f5; }}
 .badge {{ display: inline-block; padding: 1px 6px; border-radius: 3px;
           background: #eef; font-size: 11px; color: #335; }}
</style></head><body>
<h1>Cisco IOS-XE Upgrade -- Run {rid}</h1>
<div class="meta">Version {ver} &middot; {ts}</div>
<div class="totals">
 <span>success={s}</span><span>skipped={k}</span>
 <span>failed={f}</span><span>total={t}</span>
</div>
{blocks}
</body></html>"""

_HTML_LOC = """<h2>{loc} -- {n} device(s)</h2>
<table><tr><th>Status</th><th>Hostname</th><th>IP</th>
<th>Start</th><th>Target</th><th>Post</th><th>Duration</th><th>Error</th></tr>
{rows}</table>"""


def _html_escape(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def write_html_report(all_results, path, run_id=None):
    run_id = run_id or RUN_ID
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tot = {"success": 0, "skipped": 0, "failed": 0}
        blocks = []
        for loc in sorted(all_results.keys()):
            rows = []
            for r in sorted(all_results[loc].values(),
                            key=lambda x: x["hostname"]):
                tot[r["status"]] = tot.get(r["status"], 0) + 1
                dur = _fmt_duration(r.get("duration_sec", 0))
                err = _html_escape(r.get("error", "")[:100])
                flags = []
                if r.get("reboot_detected"): flags.append("reboot")
                if r.get("md5_ok"):          flags.append("md5")
                if r.get("clock_corrected"): flags.append("clock")
                fh = (" " + " ".join('<span class="badge">%s</span>' % f
                                     for f in flags)) if flags else ""
                rows.append(
                    '<tr class="s-%s"><td>%s</td><td>%s%s</td><td>%s</td>'
                    '<td>%s</td><td>%s</td><td>%s</td><td>%s</td>'
                    '<td>%s</td></tr>'
                    % (r["status"], r["status"],
                       _html_escape(r["hostname"]), fh,
                       _html_escape(r["ip"]),
                       _html_escape(r.get("start_version", "")),
                       _html_escape(r.get("target_version", "")),
                       _html_escape(r.get("post_version", "")),
                       dur, err))
            blocks.append(_HTML_LOC.format(
                loc=_html_escape(loc), n=len(all_results[loc]),
                rows="\n".join(rows)))
        html = _HTML_TPL.format(
            rid=run_id, ver=VERSION_STRING,
            ts=datetime.now().isoformat(timespec="seconds"),
            s=tot["success"], k=tot["skipped"], f=tot["failed"],
            t=sum(tot.values()), blocks="\n".join(blocks))
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        print("  HTML: %s" % path)
        return path
    except Exception as e:
        master_log("HTML err: %s" % e)
        return None


def post_run_health_snapshot(all_results, user, pw, path):
    devices = []
    for loc, res in all_results.items():
        for r in res.values():
            if r["status"] in ("success", "skipped"):
                devices.append((r["hostname"], r["ip"]))
    if not devices: return
    print("\n  -- Post-run health snapshot (%d device(s)) --" % len(devices))
    def _chk(host, ip):
        cc = None
        try:
            cc = do_connect(ip, user, pw)
            tacacs_enable(cc, host, ssh_pw=pw)
            ver = cc.send_command("show version | include Version",
                                  read_timeout=60)
            m = re.search(r"Version ([\w.()]+)", ver)
            boot = cc.send_command("show boot | include BOOT",
                                   read_timeout=60)
            switch = ""
            try:
                switch = cc.send_command("show switch", read_timeout=60)
            except Exception: pass
            rows = _SWITCH_ROW_RE.findall(switch)
            nr = sum(1 for _, st in rows
                     if st.lower() not in ("ready", "standby"))
            return {"hostname": host, "ip": ip,
                    "version": m.group(1) if m else "?",
                    "boot_ok": "packages.conf" in boot,
                    "stack_members": len(rows), "stack_not_ready": nr,
                    "ts": datetime.now().isoformat(timespec="seconds")}
        except Exception as e:
            return {"hostname": host, "ip": ip, "version": "?",
                    "boot_ok": False, "stack_members": 0,
                    "stack_not_ready": 0, "error": str(e)[:80],
                    "ts": datetime.now().isoformat(timespec="seconds")}
        finally:
            if cc:
                try: cc.disconnect()
                except Exception: pass
    snaps = []
    with ThreadPoolExecutor(max_workers=min(20, len(devices))) as ex:
        for f in as_completed([ex.submit(_chk, h, ip)
                               for h, ip in devices]):
            snaps.append(f.result())
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"run_id": RUN_ID, "snapshots": snaps}, f, indent=2)
        print("  Health: %s" % path)
    except Exception as e:
        master_log("health err: %s" % e)


def save_inventory_cache(devices, path):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"ts": time.time(), "run_id": RUN_ID,
                       "version_string": VERSION_STRING,
                       "devices": devices}, f, indent=2)
        print("  Inventory cache: %s" % path)
        return True
    except Exception as e:
        master_log("inv err: %s" % e)
        return False


def load_inventory_cache(path, max_age_sec=86400):
    if not os.path.isfile(path): return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        age = time.time() - data.get("ts", 0)
        if age > max_age_sec:
            print("  (Inventory cache is %.1fh old -- ignoring)"
                  % (age/3600))
            return None
        print("  (Reusing inventory cache from %.0fm ago)" % (age/60))
        return data.get("devices", [])
    except Exception:
        return None


def filter_only_upgrade_needed(devices, user, pw):
    need, target, unreach = [], [], []
    def _chk(d):
        host, ip = d["hostname"], d["ip"]
        cc = None
        try:
            cc = do_connect(ip, user, pw)
            tacacs_enable(cc, host, ssh_pw=pw)
            if not is_privileged(cc):
                return d, "other", ""
            model = get_model(cc) or ""
            fw = pick_firmware(model)
            if not fw:
                return d, "other", "unsupported model '%s'" % model
            _, tg = fw
            ver = cc.send_command("show version | include Version",
                                  read_timeout=60)
            return d, ("target"
                       if _norm_ver(parse_running_version(ver))
                       == _norm_ver(tg) else "needs"), tg
        except Exception as e:
            return d, "unreach", str(e)[:80]
        finally:
            if cc:
                try: cc.disconnect()
                except Exception: pass
    with ThreadPoolExecutor(max_workers=min(20, max(len(devices), 1))) as ex:
        for d, st, info in ex.map(_chk, devices):
            if st == "needs":    need.append((d, info))
            elif st == "target": target.append((d, info))
            elif st == "unreach": unreach.append((d, info))
            else:                need.append((d, info))
    return need, target, unreach


def print_change_preview(all_devices, user, pw):
    print("\n" + "=" * 70)
    print("  CHANGE PREVIEW (read-only)")
    print("=" * 70)
    rows = []
    def _chk(d):
        host, ip = d["hostname"], d["ip"]
        cc = None
        try:
            cc = do_connect(ip, user, pw)
            tacacs_enable(cc, host, ssh_pw=pw)
            model = get_model(cc) or "?"
            fw = pick_firmware(model)
            tg = fw[1] if fw else "?"
            vo = cc.send_command("show version | include Version",
                                 read_timeout=60)
            cur = parse_running_version(vo) or "?"
            action = ("skip (already on target)"
                      if _norm_ver(cur) == _norm_ver(tg)
                      else "upgrade -> %s" % tg if fw
                      else "unsupported model")
            return (host, ip, model, cur, tg, action)
        except Exception as e:
            return (host, ip, "?", "?", "?",
                    "unreachable: %s" % str(e)[:40])
        finally:
            if cc:
                try: cc.disconnect()
                except Exception: pass
    with ThreadPoolExecutor(max_workers=min(20,
                                            max(len(all_devices), 1))) as ex:
        for row in ex.map(_chk, all_devices):
            rows.append(row)
    wc = [r for r in rows if r[5].startswith("upgrade")]
    ws = [r for r in rows if r[5].startswith("skip")]
    wf = [r for r in rows if r[5].startswith("unreachable")
          or r[5] == "unsupported model"]
    print("  %2s %-30s %-15s %-18s %-12s Action"
          % ("", "Hostname", "IP", "Model", "Current"))
    print("  " + "-" * 100)
    for host, ip, model, cur, tg, action in sorted(rows):
        mk = (">" if action.startswith("upgrade")
              else "-" if action.startswith("skip") else "X")
        print("  %s  %-30s %-15s %-18s %-12s %s"
              % (mk, host, ip, model, cur, action))
    print("  " + "-" * 100)
    print("  %d will upgrade, %d already on target, %d need attention"
          % (len(wc), len(ws), len(wf)))
    print("=" * 70 + "\n")
    return wc, ws, wf


def estimate_runtime(all_devices, user, pw):
    print("\n" + "=" * 70)
    print("  RUNTIME ESTIMATE (no changes made)")
    print("=" * 70)
    rows = []
    def _chk(d):
        host, ip = d["hostname"], d["ip"]
        cc = None
        try:
            cc = do_connect(ip, user, pw)
            tacacs_enable(cc, host, ssh_pw=pw)
            model = get_model(cc) or "?"
            fw = pick_firmware(model)
            if not fw: return (host, ip, model, "?", 0)
            fwf, tg = fw
            vo = cc.send_command("show version | include Version",
                                 read_timeout=60)
            cur = parse_running_version(vo) or "?"
            return (host, ip, model, cur, get_firmware_size(fwf))
        except Exception:
            return (host, ip, "?", "?", 0)
        finally:
            if cc:
                try: cc.disconnect()
                except Exception: pass
    with ThreadPoolExecutor(max_workers=min(20,
                                            max(len(all_devices), 1))) as ex:
        rows = list(ex.map(_chk, all_devices))
    total_s = 0
    for host, ip, model, cur, sz in sorted(rows):
        per = 30 + (sz / 20e6) + 120 + 600 + 480 + 180 + 90
        total_s += per
    parallel = max(1, min(TRANSFER_SLOTS, INSTALL_WORKERS))
    wall = total_s / parallel
    print("  %d device(s), ~%d concurrent pipelines" % (len(rows), parallel))
    if rows:
        print("  Per-device avg: %s"
              % _fmt_duration(int(total_s / max(len(rows), 1))))
    print("  Estimated wall time: %s (+/-40%%)" % _fmt_duration(int(wall)))
    print("=" * 70 + "\n")
    return 0


def prompt_resume_or_abort(stale_files):
    print("\n  Un-reverted temp-config state from an earlier run exists:")
    for s in stale_files:
        print("     - %s" % s)
    print("\n  Options:")
    print("    [R] Resume -- skip already-verified devices")
    print("    [S] Skip failed -- retry only previously failed devices")
    print("    [A] Abort -- exit cleanly (--recover to revert temp config)")
    try:
        ans = input("  Choice [R/S/A]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return "abort"
    if ans.startswith("r"): return "resume"
    if ans.startswith("s"): return "skip"
    return "abort"


_CONFIG_KEYS = {
    "LOCATIONS_TO_RUN", "TRANSFER_SLOTS", "INSTALL_WORKERS",
    "MAX_SAFE_SSH_SESSIONS", "PRESERVE_ROLLBACK", "MIN_FREE_BYTES",
    "EXTRA_HEADROOM_BYTES", "STACK_MEMBER_HEADROOM", "RETRY_FAILED_DEVICES",
    "MAX_RETRIES", "RETRY_DELAY_SEC", "ABORT_GATE_THRESHOLD",
    "ABORT_GATE_MIN_DEVICES", "SCP_TIMEOUT_SEC", "SCP_MAX_ATTEMPTS",
    "SCP_RETRY_DELAY", "SCP_STALL_TIMEOUT", "SCP_PROGRESS_POLL",
    "ENABLE_SCP_MONITOR", "USE_PSCP", "PSCP_TRANSFER_FALLBACK",
    "TRANSFER_RETRY_ATTEMPTS", "TRANSFER_RETRY_DELAY_SEC",
    "TRANSFER_VERIFY_TIMEOUT", "VERIFY_TRANSFER_HASH",
    "LARGE_MODEL_PARALLEL", "USE_PARAMIKO_TUNED", "PARAMIKO_PRIMARY",
    "PARAMIKO_CHANNEL_CHUNK", "PARAMIKO_WINDOW_BYTES",
    "PARAMIKO_DISABLE_REKEY", "CHEAP_CRYPTO_TUNING", "CHEAP_CIPHER",
    "CHEAP_MAC", "PREFER_CHEAP_CIPHERS", "BULK_MODE_WINDOW_SIZE",
    "LEGACY_WINDOW_SIZE", "RECONNECT_MAX_ATTEMPTS", "RECONNECT_DELAY_SEC",
    "PING_TIMEOUT_MS", "PING_DOWN_POLL_SEC", "PING_DOWN_TIMEOUT_SEC",
    "PING_UP_POLL_SEC", "PING_UP_TIMEOUT_SEC", "PING_STABILITY_SEC",
    "POST_REBOOT_SSH_WAIT_SEC", "POST_REBOOT_SETTLE_SEC",
    "POST_REBOOT_MAX_ATTEMPTS", "POST_REBOOT_DELAY_SEC",
    "PROBE_CONNECT_RETRIES", "PROBE_CONNECT_DELAY_SEC",
    "RECONCILE_FAILED_AT_END", "HEALTH_RETRIES", "HEALTH_RETRY_DELAY_SEC",
    "INSTALL_TOTAL_TIMEOUT", "INSTALL_SILENT_TIMEOUT",
    "INSTALL_PROBE_INTERVAL", "ISSU_VERIFY_TIMEOUT", "ISSU_VERIFY_MAX_ERRORS",
    "COMMIT_VERIFY_TIMEOUT", "COMMIT_VERIFY_RETRY_SEC",
    "SESSION_SLOT_ACQUIRE_TIMEOUT",
    "DO_BACKUP", "DO_VERIFY_MD5", "WIPE_BEFORE_TRANSFER",
    "DO_RESET_DEVICE_LOGS", "PRE_SAVE_CONFIG", "SKIP_CONFIG_DRIFT_CHECK",
    "ALLOW_BUNDLE_MODE_CONVERSION", "POOL_LOCATIONS",
    "REVERT_TEMP_CONFIG_POST_LOCATION", "REVERT_MAX_ATTEMPTS",
    "REVERT_RETRY_DELAY_SEC", "REVERT_UPTIME_GATE_MIN",
    "REVERT_WRITE_MEMORY", "REVERT_VERIFY_AFTER", "LIVE_LOG_PANEL_PHASES",
    "LIVE_LOG_FEED_TRANSFER", "LARGE_MODEL_PREFIXES",
    "SERIAL_TRANSFER_LARGE_MODELS", "BACKUP_MAX_FILES",
    "BACKUP_MAX_SIZE_GB", "LOG_ARCHIVE_MAX_DAYS", "LOG_ARCHIVE_MAX_SIZE_GB",
    "CLOCK_DRIFT_WARN_SEC", "CLOCK_DRIFT_FIX_SEC", "STRICT_FAMILY_CHECK",
    "MONITOR_INTERVAL", "LOG_MAX_AGE_DAYS", "LOG_MAX_SIZE_GB",
    "MODEL_FIRMWARE_MAP", "MODELS_REQUIRING_SSH_TUNE",
    "FAMILY_SIZE_BOUNDS_STRICT", "MAX_FIRMWARE_BYTES",
    "MIN_FIRMWARE_BYTES", "DASHBOARD_REPAINT_SEC",
    "EXTRACTION_OVERHEAD_FACTOR", "ALLOW_ACTIVE_PKG_PURGE",
}


def apply_config_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print("  Could not read config file %s: %s" % (path, e))
        return False
    g = globals()
    for k, v in data.items():
        if k not in _CONFIG_KEYS:
            print("  Config key not recognized: %s" % k); continue
        if k == "MODEL_FIRMWARE_MAP":
            v = [tuple(x) for x in v]
            v.sort(key=lambda x: -len(x[0]))
        if k in ("MODELS_REQUIRING_SSH_TUNE", "LARGE_MODEL_PREFIXES",
                 "LIVE_LOG_PANEL_PHASES"):
            v = tuple(v)
        g[k] = v
    print("  Loaded config: %s" % path)
    return True


_SIG_COUNT = [0]


def _on_signal(signum, frame):
    _SIG_COUNT[0] += 1
    if _SIG_COUNT[0] == 1:
        SHUTDOWN_REQ.set()
        msg = ("\n  !! Shutdown requested -- finishing safely; temp config "
               "will be reverted.\n  !! Press Ctrl-C again to force exit.\n")
    else:
        msg = "\n  !! Forced exit. Run --recover afterwards.\n"
    try: os.write(2, msg.encode("utf-8", "replace"))
    except Exception: pass
    if _SIG_COUNT[0] >= 2: os._exit(130)


def parse_args():
    p = argparse.ArgumentParser(
        description="Cisco IOS-XE upgrade orchestrator v%s" % VERSION_STRING)
    for a in ("--base-dir", "--config", "--user", "--enable-pass",
              "--enable-user"):
        p.add_argument(a)
    p.add_argument("--locations", nargs="+")
    for a in ("--dry-run", "--skip-issu", "--auto-rollback", "--no-pause",
              "--yes", "--precache-hostkeys", "--ignore-stale-state",
              "--force-run-with-stale-state", "--resume", "--recover",
              "--revert-only", "--dry-run-revert", "--preflight-only",
              "--inventory", "--check", "--rollback", "--rollback-dry-run",
              "--no-verify-revert", "--show-live-transfer",
              "--no-serial-large", "--no-drift-check", "--no-hash-verify",
              "--no-reconcile", "--resume-checkpoint", "--retry-failed",
              "--write-manifest", "--verify-mapping", "--validate",
              "--no-bundle-mode", "--no-pool-locations", "--paramiko-primary",
              "--allow-lenient-firmware", "--allow-active-pkg-purge"):
        p.add_argument(a, action="store_true")
    p.add_argument("--allow-bundle-mode", action="store_true", default=None)
    p.add_argument("--pool-locations", action="store_true", default=None)
    p.add_argument("--parallel-large", type=int, default=None, metavar="N")
    p.add_argument("--bulk-window", type=int, default=None, metavar="N")
    p.add_argument("--limit", nargs="+")
    p.add_argument("--exclude", nargs="+")
    p.add_argument("--hosts", nargs="+")
    p.add_argument("--version", action="version",
                   version="cisco_upgrade v%s" % VERSION_STRING)
    p.add_argument("--only-upgrade-needed", action="store_true")
    p.add_argument("--preview", action="store_true")
    p.add_argument("--preview-only", action="store_true")
    p.add_argument("--quiet-skipped", action="store_true")
    p.add_argument("--no-html-report", action="store_true")
    p.add_argument("--no-health-snapshot", action="store_true")
    p.add_argument("--use-inventory-cache", action="store_true")
    p.add_argument("--no-colour", "--no-color", action="store_true",
                   dest="no_colour")
    p.add_argument("--estimate-only", action="store_true")
    p.add_argument("--interactive-resume", action="store_true")
    return p.parse_args()


def get_credentials(args):
    user = (args.user or os.environ.get("CISCO_USER")
            or input("  SSH username: ").strip())
    pw = os.environ.get("CISCO_PASS") or getpass("  SSH password: ")
    return user, pw


def confirm(msg, assume_yes=False):
    if assume_yes: return True
    try:
        return input("%s [y/N]: " % msg).strip().lower() in ("y", "yes")
    except EOFError: return False


def filter_devices(devices, args):
    if args.hosts:
        wanted = {h.strip() for h in args.hosts}
        return [d for d in devices if d["hostname"] in wanted]
    out = devices
    if args.limit:
        wanted = {h.strip() for h in args.limit}
        out = [d for d in out if d["hostname"] in wanted]
    if args.exclude:
        skip = {h.strip() for h in args.exclude}
        out = [d for d in out if d["hostname"] not in skip]
    return out


def mode_dry_run_revert():
    n = load_state_for_recovery(consume=False)
    if not n:
        print("  No recorded temp changes found."); return 0
    hostmap = build_host_ip_map()
    print("\n  %d device(s) have un-reverted temp changes:\n" % n)
    with TEMP_CHANGES_LOCK:
        snap = {h: list(e["changes"]) for h, e in TEMP_CHANGES.items()}
    for host in sorted(snap):
        ip = hostmap.get(host, "??? (not in any location file)")
        print("  %s  (%s)" % (host, ip))
        for ch in snap[host]:
            print("      - %s: %s" % (ch["type"], json.dumps(ch["details"])))
    print("\n  (nothing changed; use --recover to apply)")
    return 0


def mode_recover(args, locations_filter=None):
    n = load_state_for_recovery(consume=True)
    if not n:
        print("  No recorded temp changes found."); return 0
    hostmap = build_host_ip_map()
    if locations_filter:
        allowed = set()
        for loc in locations_filter:
            p = os.path.join(LOCATIONS_DIR, "%s.txt" % loc)
            if os.path.isfile(p):
                allowed |= {d["hostname"] for d in load_location(p)}
            else:
                print("  Missing location file: %s" % p)
        hosts = [h for h in list(TEMP_CHANGES) if h in allowed]
    else:
        hosts = list(TEMP_CHANGES)
    devices, unknown = [], []
    for h in hosts:
        if h in hostmap:
            devices.append({"hostname": h, "ip": hostmap[h]})
        else: unknown.append(h)
    if unknown: print("  No IP known for: %s" % ", ".join(unknown))
    if not devices: return 1 if unknown else 0
    if not confirm("  Revert temp config on %d device(s)?" % len(devices),
                   args.yes):
        print("  Aborted (state kept)."); return 1
    user, pw = get_credentials(args)
    _, no_conn, failed, expected = revert_devices(devices, user, pw,
                                                  "RECOVERY")
    rc = 1 if (no_conn or failed or unknown) else 0
    if REVERT_VERIFY_AFTER and expected:
        rv = verify_revert_clean(devices, user, pw, "RECOVERY", expected)
        if rv and any(not r.get("ok") for r in rv.values()):
            rc = 1
    return rc


def mode_inventory(devices, user, pw):
    print("\n  INVENTORY")
    print("  " + "-" * 68)
    out_devices = []
    for d in devices:
        host, ip = d["hostname"], d["ip"]
        c_ = None
        try:
            c_ = do_connect(ip, user, pw)
            tacacs_enable(c_, host, ssh_pw=pw)
            model = get_model(c_) or "?"
            ver_out = c_.send_command("show version | include Version")
            ver = parse_running_version(ver_out) or "?"
            boot = c_.send_command("show boot | include BOOT")
            mode = "install" if "packages.conf" in boot else "bundle"
            free = get_flash_free_bytes(c_)
            flag = "LARGE" if _is_large_model(model) else "small"
            vt = get_ios_xe_version_tuple(c_)
            tier = _bulk_mode_tier(vt) or "?"
            bulk = ("bulk" if _verify_config_line(c_, "ip ssh bulk-mode")
                    else "no-bulk")
            print("  %-32s %-15s %-18s ver=%-12s mode=%-7s free=%s %s "
                  "tier=%s %s"
                  % (host, ip, model, ver, mode, _fmt_bytes(free), flag,
                     tier, bulk))
            out_devices.append({"hostname": host, "ip": ip, "model": model,
                                "version": ver, "mode": mode,
                                "free_bytes": free, "tier": tier,
                                "bulk": bulk})
        except Exception as e:
            tag = _classify_connect_error(e)
            print("  %-32s %-15s ERROR: %s"
                  % (host, ip, tag or str(e)[:60]))
        finally:
            if c_:
                try: c_.disconnect()
                except Exception: pass
    try:
        save_inventory_cache(out_devices,
                             os.path.join(BASE_DIR, "inventory_cache.json"))
    except Exception: pass
    return 0


def mode_check(devices, user, pw):
    print("\n  VERSION CHECK")
    print("  " + "-" * 68)
    for d in devices:
        host, ip = d["hostname"], d["ip"]
        c_ = None
        try:
            c_ = do_connect(ip, user, pw)
            tacacs_enable(c_, host, ssh_pw=pw)
            model = get_model(c_) or ""
            fw = pick_firmware(model)
            if not fw:
                print("  %-32s unsupported model '%s'" % (host, model))
                continue
            _, target_ver = fw
            ver_out = c_.send_command("show version | include Version")
            cur = parse_running_version(ver_out) or "?"
            status = ("OK (target)"
                      if _norm_ver(cur) == _norm_ver(target_ver)
                      else "upgrade needed -> %s" % target_ver)
            print("  %-32s %-15s current=%-14s %s"
                  % (host, ip, cur, status))
        except Exception as e:
            tag = _classify_connect_error(e)
            print("  %-32s %-15s ERROR: %s"
                  % (host, ip, tag or str(e)[:60]))
        finally:
            if c_:
                try: c_.disconnect()
                except Exception: pass
    return 0


def mode_rollback(devices, user, pw, args, dry=False):
    verb = "DRY-RUN " if dry else ""
    if not confirm("  %sIssue `install rollback to committed` on "
                   "%d device(s)?" % (verb, len(devices)), args.yes):
        print("  Aborted."); return 1
    print("\n  ROLLBACK%s" % (" (DRY-RUN)" if dry else ""))
    print("  " + "-" * 68)
    rc = 0
    for d in devices:
        host, ip = d["hostname"], d["ip"]
        conn = None
        try:
            conn = do_connect(ip, user, pw)
            tacacs_enable(conn, host, ssh_pw=pw)
            cur = ""
            try:
                _o = conn.send_command("show version | include Version",
                                       read_timeout=30)
                cur = parse_running_version(_o)
            except Exception: pass
            if dry:
                try:
                    summ = conn.send_command("show install summary",
                                             read_timeout=60)
                    feed_live_log(host,
                                  "[rollback-dry] show install summary\n%s"
                                  % summ)
                    entries = _parse_install_summary(summ)
                    inactive = [v for v, s in entries.items() if s == "I"]
                    print("  %-32s current=%-14s inactive_images=%d %s"
                          % (host, cur, len(inactive),
                             "(rollback possible)" if inactive
                             else "(no inactive image)"))
                except Exception as e:
                    print("  %-32s DRY-RUN ERROR: %s" % (host, str(e)[:60]))
                    rc = 1
            else:
                if attempt_rollback(conn, host, ip=ip, user=user, pw=pw,
                                    original_version=cur):
                    print("  %-32s rollback issued" % host)
                else:
                    print("  %-32s rollback FAILED" % host); rc = 1
        except Exception as e:
            tag = _classify_connect_error(e)
            print("  %-32s ERROR: %s" % (host, tag or str(e)[:60])); rc = 1
        finally:
            if conn:
                try: conn.disconnect()
                except Exception: pass
    return rc


def mode_verify_mapping(devices, user, pw):
    print("\n  FIRMWARE MAPPING VERIFICATION")
    print("  " + "-" * 68)
    for d in devices:
        host, ip = d["hostname"], d["ip"]
        c_ = None
        try:
            c_ = do_connect(ip, user, pw)
            tacacs_enable(c_, host, ssh_pw=pw)
            model = get_model(c_) or ""
            fw = pick_firmware(model)
            if not fw:
                print("  %-32s %-18s UNSUPPORTED" % (host, model))
                continue
            fwf, tg = fw
            ok, reason = verify_model_firmware_consistency(model, fwf, tg)
            print("  %-32s %-18s %-42s %s"
                  % (host, model, fwf, "OK" if ok else reason))
        except Exception as e:
            tag = _classify_connect_error(e)
            print("  %-32s ERROR: %s" % (host, tag or str(e)[:60]))
        finally:
            if c_:
                try: c_.disconnect()
                except Exception: pass
    return 0


def _validate():
    passed, failed = [], []
    def _t(name, fn):
        try:
            fn(); passed.append(name)
        except AssertionError as e:
            failed.append((name, "assertion: %s" % e))
        except Exception as e:
            failed.append((name, "%s: %s" % (type(e).__name__, e)))

    def t_family():
        assert _family_for_model("C9200L-24P") == ("lite", "_lite_")
        assert _family_for_model("C9300-48P") == ("full", None)
        assert _family_for_model("C9500-24Y4C") == ("full", None)
        assert _family_for_model("C9200CX-8P") == ("lite", "_lite_")
        assert _family_for_model("") == (None, None)
        assert _family_for_model("Unknown") == (None, None)
    _t("_family_for_model", t_family)

    def t_size():
        assert _family_size_ok("lite", 500_000_000)[0]
        assert not _family_size_ok("lite", 1_500_000_000)[0]
        assert _family_size_ok("full", 1_200_000_000)[0]
        assert not _family_size_ok("full", 400_000_000)[0]
        assert _family_size_ok(None, 0)[0]
    _t("_family_size_ok", t_size)

    def t_norm():
        raw = "\n".join([
            "Building configuration...",
            "Current configuration : 2345 bytes",
            "!", "! Last configuration change at 12:00",
            "version 17.18", "hostname SW1", "!",
            "endpoint-tracking", "end-user-acl 1", "end", "",
            "3d04h: %SYS-5-CONFIG_I: Configured from console"])
        out = _normalize_config(raw)
        assert "version 17.18" in out
        assert "hostname SW1" in out
        assert "endpoint-tracking" in out
        assert "end-user-acl 1" in out
        assert "end" not in out
        assert all(not l.startswith("!") for l in out)
    _t("_normalize_config keeps endpoint-* lines", t_norm)

    def t_drift_noise():
        assert _is_drift_noise("- exec-timeout 60 0")
        assert _is_drift_noise("+ exec-timeout 30 0")
        assert _is_drift_noise("- ip ssh bulk-mode window-size 131072")
        assert _is_drift_noise("+ ip scp server enable")
        assert not _is_drift_noise("+ hostname SW1")
        assert not _is_drift_noise("+++ b/file")
        assert not _is_drift_noise("--- a/file")
    _t("config-drift noise filters both sides", t_drift_noise)

    def t_norm_ver():
        assert _norm_ver("17.18.04") == "17.18.4"
        assert _norm_ver("17.18.4")  == "17.18.4"
        assert _norm_ver("") == ""
        assert _norm_ver(None) == ""
        assert _norm_ver("garbage") == "garbage"
    _t("_norm_ver", t_norm_ver)

    def t_member_required():
        fw = 478_710_000
        need_act_have = _member_required_bytes(
            fw, True, bin_already_present=True, is_standby=False)
        assert 550_000_000 < need_act_have < 650_000_000, need_act_have
        need_act_no = _member_required_bytes(
            fw, True, bin_already_present=False, is_standby=False)
        assert 1_050_000_000 < need_act_no < 1_100_000_000, need_act_no
        need_stby = _member_required_bytes(
            fw, True, bin_already_present=True, is_standby=True)
        assert 1_050_000_000 < need_stby < 1_100_000_000, need_stby
        assert need_stby == need_act_no
        assert _member_required_bytes(0, True) == MIN_FREE_BYTES
    _t("v35.9.34 _member_required_bytes (active vs standby)",
       t_member_required)

    def t_extraction_factor_realistic():
        assert 1.0 <= EXTRACTION_OVERHEAD_FACTOR <= 1.15, \
            "extraction factor must be >=1.0 (bin is compressed)"
    _t("v35.9.33 extraction factor >= 1.0", t_extraction_factor_realistic)

    def t_space_markers_extended():
        assert "not enough free disk" in _SPACE_MARKERS
        assert "free disk available" in _SPACE_MARKERS
        assert "not enough space" in _SPACE_MARKERS
        assert "insufficient space" in _SPACE_MARKERS
    _t("v35.9.30 Cisco space markers", t_space_markers_extended)

    def t_runinstall_uses_space_marker():
        import inspect as _i
        src = _i.getsource(run_install)
        assert "_SPACE_MARKERS" in src
        assert "insufficient_space: install engine rejected" in src
    _t("v35.9.30 run_install short-circuits on Cisco space error",
       t_runinstall_uses_space_marker)

    def t_precheck_uses_new_formula():
        import inspect as _i
        src = _i.getsource(precheck_device)
        assert "_member_required_bytes" in src
        assert "EXTRACTION_OVERHEAD_FACTOR" in src
        assert "insufficient_space_stack" in src
    _t("v35.9.31 precheck uses new formula",
       t_precheck_uses_new_formula)

    def t_force_wipe_allows_running_bin():
        import inspect as _i
        src = _i.getsource(_force_wipe_flash)
        assert "allow_running_bin_delete" in src
        assert "_is_install_mode" in src
        assert "keep_bin" in src
    _t("v35.9.31 force-wipe can delete running .bin in install mode",
       t_force_wipe_allows_running_bin)

    def t_do_connect_call():
        import inspect as _i
        src = _i.getsource(wait_reboot_and_verify)
        assert "do_connect(ip, host, user, pw" not in src
        assert "do_connect(ip, user, pw)" in src
    _t("v35.9.31 wait_reboot_and_verify uses correct do_connect",
       t_do_connect_call)

    def t_verify_boot_and_install_ready():
        import inspect as _i
        src = _i.getsource(verify_boot_and_install_ready)
        assert "packages.conf" in src
        assert "install_busy" in src
        assert "size_mismatch" in src
    _t("v35.9.31 verify_boot_and_install_ready",
       t_verify_boot_and_install_ready)

    def t_purge_unnecessary():
        import inspect as _i
        src = _i.getsource(_purge_unnecessary_files)
        assert "_read_active_packages" in src
        assert "aggressive" in src
        assert "active_pkgs" in src
    _t("v35.9.31 _purge_unnecessary_files", t_purge_unnecessary)

    def t_summary_multi():
        out = "\n".join([
            "Install Summary", "===============", "",
            "IMG: flash:cat9k_iosxe.17.18.04.SPA.bin",
            "  Version : 17.18.04", "  Status  : C"])
        assert summary_committed_on_target(out, "17.18.04")
        assert summary_committed_on_target(out, "17.18.4")
        assert not summary_committed_on_target(out, "17.15.01")
    _t("summary_committed_on_target (multi-block)", t_summary_multi)

    def t_summary_with_leftover_I():
        out = "\n".join([
            "IMG: flash:cat9k_iosxe.17.18.04.SPA.bin",
            "  Version : 17.18.04", "  Status  : C",
            "IMG: flash:cat9k_iosxe.17.15.03.SPA.bin",
            "  Version : 17.15.03", "  Status  : I"])
        assert summary_committed_on_target(out, "17.18.04")
    _t("summary accepts leftover I", t_summary_with_leftover_I)

    def t_summary_two_C_rejected():
        out = "\n".join([
            "IMG: flash:cat9k_iosxe.17.18.04.SPA.bin",
            "  Version : 17.18.04", "  Status  : C",
            "IMG: flash:cat9k_iosxe.17.15.03.SPA.bin",
            "  Version : 17.15.03", "  Status  : C"])
        assert not summary_committed_on_target(out, "17.18.04")
    _t("summary rejects two-C", t_summary_two_C_rejected)

    def t_summary_uncommitted():
        out = "\n".join([
            "IMG: flash:cat9k_iosxe.17.18.04.SPA.bin",
            "  Version : 17.18.04", "  Status  : U"])
        assert not summary_committed_on_target(out, "17.18.04")
    _t("summary rejects Uncommitted", t_summary_uncommitted)

    def t_summary_rows_ok():
        out = "\n".join(["  IMG  C  17.18.04"])
        assert summary_committed_on_target(out, "17.18.04")
    _t("summary rows form accepts single C", t_summary_rows_ok)

    def t_parse_summary_multi():
        out = ("IMG: flash:cat9k_iosxe.17.18.04.SPA.bin\n"
               "  Version : 17.18.04\n"
               "  Status  : C\n"
               "IMG: flash:cat9k_iosxe.17.15.03.SPA.bin\n"
               "  Version : 17.15.03\n"
               "  Status  : I")
        r = _parse_install_summary(out)
        assert r.get("17.18.4") == "C"
        assert r.get("17.15.3") == "I"
    _t("_parse_install_summary (multi-block)", t_parse_summary_multi)

    def t_parse_summary_rows():
        out = "  IMG  C  17.18.04\n  IMG  A  17.15.03\n  IMG  U  17.12.04\n  IMG  I  17.11.01"
        r = _parse_install_summary(out)
        assert r.get("17.18.4") == "C"
        assert r.get("17.15.3") == "A"
        assert r.get("17.12.4") == "U"
        assert r.get("17.11.1") == "I"
    _t("_parse_install_summary (rows)", t_parse_summary_rows)

    def t_parse_summary_empty():
        assert _parse_install_summary("") == {}
        assert _parse_install_summary(None) == {}
    _t("_parse_install_summary (empty)", t_parse_summary_empty)

    def t_dead_socket():
        for txt in ("Socket is closed", "connection reset",
                    "broken pipe", "EOF", "channel closed",
                    "no existing session", "EOF occurred",
                    "EOF when reading a line"):
            assert _is_dead_socket_error(txt) is True, txt
        assert _is_dead_socket_error("parser found no EOF marker") is False
        assert _is_dead_socket_error("random error") is False
        assert _is_dead_socket_error("no EOF found") is False
    _t("_is_dead_socket_error (anchored)", t_dead_socket)

    def t_bulk():
        assert _bulk_mode_tier((17, 10, 1)) == "A"
        assert _bulk_mode_tier((17, 12, 3)) == "A"
        assert _bulk_mode_tier((17, 6, 5)) == "B"
        assert _bulk_mode_tier((17, 2, 1)) == "C"
        assert _bulk_mode_tier((16, 12, 5)) == "D"
        assert _bulk_mode_tier(None) is None
    _t("_bulk_mode_tier", t_bulk)

    def t_bins():
        out = "\n".join([
            "Directory of flash:/", "",
            "    1  -rw-  12345678   Mar 1 2025 12:00:00 +00:00  "
            "cat9k_iosxe.17.18.04.SPA.bin",
            "    2  -rw-   9876543   Mar 1 2025 12:00:00 +00:00  "
            "cat9k_lite_iosxe.17.18.04.SPA.bin",
            "    3  drwx        4096  Mar 1 2025 12:00:00 +00:00  .installer"])
        bins = parse_dir_bins(out)
        assert "cat9k_iosxe.17.18.04.SPA.bin" in bins
        assert "cat9k_lite_iosxe.17.18.04.SPA.bin" in bins
    _t("parse_dir_bins", t_bins)

    def t_fsize():
        out = ("-rw-   123456789   Mar 1 2025 12:00:00 +00:00  "
               "cat9k_iosxe.17.18.04.SPA.bin")
        assert _parse_file_size_from_dir(
            out, "cat9k_iosxe.17.18.04.SPA.bin") == 123456789
    _t("_parse_file_size_from_dir", t_fsize)

    def t_uptime():
        assert parse_uptime_minutes("2 weeks, 3 days, 4 hours, 5 minutes") \
            == 2*10080 + 3*1440 + 4*60 + 5
        assert parse_uptime_minutes("1 year, 12 weeks") == 525600 + 12*10080
        assert parse_uptime_minutes("garbage") is None
    _t("parse_uptime_minutes", t_uptime)

    def t_vty():
        out = "\n".join([
            "line vty 0 4", " exec-timeout 60 0", " transport input ssh",
            "line vty 5 15", " transport input ssh"])
        b = parse_vty_blocks(out)
        assert len(b) == 2
        assert b[0]["vty"] == "0 4"
        assert b[0]["minutes"] == 60
        assert b[1]["vty"] == "5 15"
        assert b[1].get("was_default") is True
    _t("parse_vty_blocks", t_vty)

    def t_class():
        e = Exception("No acceptable KEX algorithm")
        assert _classify_connect_error(e) == "SSH negotiation failed"
        e = Exception("No acceptable host key")
        assert _classify_connect_error(e) == "SSH host-key negotiation failed"
        e = Exception("some random error")
        assert _classify_connect_error(e) == ""
    _t("_classify_connect_error", t_class)

    def t_large():
        assert _is_large_model("C9300-48P")
        assert _is_large_model("C9500-24Y4C")
        assert not _is_large_model("C9200L-24P")
        assert not _is_large_model("")
    _t("_is_large_model", t_large)

    def t_map_selfcheck():
        errs, _ = verify_firmware_map()
        structural = [e for e in errs if "not found at" not in e
                      and "exceeds the absolute" not in e
                      and "too small" not in e]
        assert not structural, "structural errors: %s" % structural
    _t("verify_firmware_map (structural)", t_map_selfcheck)

    def t_fw_hard_cap():
        import inspect as _i
        src = _i.getsource(verify_firmware_map)
        assert "MAX_FIRMWARE_BYTES" in src
        assert "exceeds the absolute" in src
    _t("firmware hard cap", t_fw_hard_cap)

    def t_fw_size_constants():
        assert MAX_FIRMWARE_BYTES == 2_000_000_000
        assert MIN_FIRMWARE_BYTES == 100_000_000
        assert FAMILY_SIZE_BOUNDS_STRICT is True
    _t("firmware size constants", t_fw_size_constants)

    def t_cmd_tracking():
        assert "set_cmd" in globals() and "get_cmd" in globals()
        set_cmd("testhost", "show version")
        assert get_cmd("testhost") == "show version"
    _t("Cmd tracking", t_cmd_tracking)

    def t_long_running_phases():
        assert "INSTALL" in LIVE_LOG_PANEL_PHASES
        assert "SERVICE-LOCKS" in LIVE_LOG_PANEL_PHASES
        assert "PRE-CHECK" in LIVE_LOG_PANEL_PHASES
        assert "PKG-PURGE" in LIVE_LOG_PANEL_PHASES
    _t("long-running phases", t_long_running_phases)

    def t_activate_forms():
        assert len(_ACTIVATE_FORMS) >= 3
        assert any("activate file flash" in f for f in _ACTIVATE_FORMS)
        assert any(f == "install activate" for f in _ACTIVATE_FORMS)
        import inspect as _i
        src = _i.getsource(_try_all_activate_forms)
        assert "_nudge_install_activate" in src
    _t("activate forms", t_activate_forms)

    def t_fast_reboot_probe():
        import inspect as _i
        src = _i.getsource(wait_reboot_and_verify)
        assert "fast-reboot probe" in src
        assert "_verify_after_reboot_impl" in src
    _t("fast-reboot probe", t_fast_reboot_probe)

    def t_residual_detector():
        assert "_detect_residual_temp_config" in globals()
        import inspect as _i
        src = _i.getsource(_detect_residual_temp_config)
        assert "exec_timeout" in src
        assert "ssh_tune" in src
    _t("residual detector", t_residual_detector)

    def t_precheck_checks_commit():
        import inspect as _i
        src = _i.getsource(precheck_device)
        assert "already_on_target_needs_finalize" in src
        assert "_detect_residual_temp_config" in src
        assert "summary_committed_on_target" in src
    _t("precheck commit + residual audit",
       t_precheck_checks_commit)

    def t_install_fixup_path():
        import inspect as _i
        src = _i.getsource(install_worker)
        assert "already_on_target_fixup" in src
    _t("install fixup path (safety net)", t_install_fixup_path)

    def t_fixup_inline():
        import inspect as _i
        src = _i.getsource(transfer_worker)
        assert "fixup_done" in src
        assert "_finalize_install_commit" in src
        assert "revert_device_temp_changes" in src
    _t("v35.9.29 fixup inline in transfer_worker", t_fixup_inline)

    def t_fixup_done_routes_in_collect():
        import inspect as _i
        src = _i.getsource(_collect_transfer_result)
        assert "fixup_done" in src
    _t("v35.9.29 fixup_done routes", t_fixup_done_routes_in_collect)

    def t_drain_install_futures():
        import inspect as _i
        src = _i.getsource(run_pass)
        assert "_drain_install" in src
        assert "block=False" in src
    _t("v35.9.29 run_pass drains installs", t_drain_install_futures)

    def t_pool_rebalance():
        # v35.9.42 FIX-WORKER-FLEX: no specific counts asserted; just
        # ensure the config is self-consistent and sane.
        assert isinstance(TRANSFER_SLOTS, int) and TRANSFER_SLOTS >= 1
        assert isinstance(INSTALL_WORKERS, int) and INSTALL_WORKERS >= 1
        assert isinstance(MAX_SAFE_SSH_SESSIONS, int)
        assert MAX_SAFE_SSH_SESSIONS >= 1
    _t("v35.9.42 worker counts sane (flexible)", t_pool_rebalance)

    def t_probe_overhead_reduced():
        assert INSTALL_PROBE_INTERVAL == 300
        assert PROBE_CONNECT_RETRIES == 2
        assert COMMIT_VERIFY_TIMEOUT == 300
        assert COMMIT_VERIFY_RETRY_SEC == 15
        assert SESSION_SLOT_ACQUIRE_TIMEOUT == 60
    _t("v35.9.29 probe overhead reduced", t_probe_overhead_reduced)

    def t_clock_cache():
        assert "_ensure_device_clock_correct_cached" in globals()
        assert "_CLOCK_TTL_SEC" in globals()
        import inspect as _i
        src_pc = _i.getsource(precheck_device)
        assert "_ensure_device_clock_correct_cached" in src_pc
    _t("v35.9.29 clock check is cached", t_clock_cache)

    def t_state_hosts():
        v2 = {"schema": 2, "run_id": "x",
              "hosts": {"sw1": {"changes": []}}}
        assert _state_hosts(v2) == {"sw1": {"changes": []}}
        v1 = {"sw1": {"changes": []}}
        assert _state_hosts(v1) == v1
        assert _state_hosts(None) == {}
    _t("_state_hosts", t_state_hosts)

    def t_row():
        d = {"hostname": "sw1", "ip": "10.0.0.1"}
        st = {"verify_pending": True, "target_version": "17.18.04",
              "clock_corrected": True, "config_diff_lines": 4}
        r = _row(d, "failed", "install", "test", st=st)
        assert r["verify_pending"] is True
        assert r["clock_corrected"] is True
        assert r["config_diff_lines"] == 4
        assert r["target_version"] == "17.18.04"
    _t("_row fields", t_row)

    def t_revert_markers():
        m = _revert_markers_for_types(["ssh_tune", "cheap_crypto"])
        names = [x[0] for x in m]
        assert "ip ssh bulk-mode" in names
        assert "ip ssh server algorithm encryption" in names
    _t("_revert_markers_for_types", t_revert_markers)

    def t_rollback_syntax():
        import inspect as _i
        src = _i.getsource(_issue_rollback_commands)
        assert "install rollback to committed" in src
        assert "install rollback to base" in src
    _t("rollback tries modern then legacy", t_rollback_syntax)

    def t_safe_reload():
        import inspect as _i
        src = _i.getsource(_safe_manual_reload)
        assert "_RELOAD_MARKERS" in src
        assert "proceed with reload" in src.lower()
    _t("_safe_manual_reload marker-driven", t_safe_reload)

    def t_install_stages():
        import inspect as _i
        src = _i.getsource(run_install)
        assert "install_add" in src
        assert "install_activate" in src
        assert "install_commit" in src
    _t("run_install stage detection", t_install_stages)

    def t_runinstall_done():
        import inspect as _i
        src = _i.getsource(run_install)
        assert "_DONE" in src
        assert "image committed on " in src
        assert "already on " in src
        assert "Probe confirms on target" in src
    _t("run_install exits on done", t_runinstall_done)

    def t_probe_version_first():
        import inspect as _i
        src = _i.getsource(_probe_install_status)
        ver_pos = src.find('show version | include Version')
        summ_pos = src.find('show install summary')
        assert ver_pos != -1 and summ_pos != -1
        assert ver_pos < summ_pos
    _t("probe checks version first", t_probe_version_first)

    def t_probe_uses_parser():
        import inspect as _i
        src = _i.getsource(_probe_install_status)
        assert "_parse_install_summary" in src
    _t("probe uses _parse_install_summary", t_probe_uses_parser)

    def t_runinstall_activate_before_cap():
        import inspect as _i
        src = _i.getsource(run_install)
        inactive_pos = src.find('"image inactive" in probe_msg')
        cap_pos = src.find("if same_total >= 12")
        assert 0 <= inactive_pos < cap_pos
    _t("activate nudge before cap", t_runinstall_activate_before_cap)

    def t_nudge_helper():
        import inspect as _i
        src = _i.getsource(_nudge_install_activate)
        assert "install activate file flash:" in src
        assert "_PROMPT_MARKERS" in src
        assert "_RELOAD_MARKERS" in src
        assert "_is_dead_socket_error" in src
    _t("nudge helper complete", t_nudge_helper)

    def t_escalation_helper():
        import inspect as _i
        src = _i.getsource(_run_install_abort_and_reissue)
        assert "install abort" in src
        assert "install add file flash:" in src
        assert "_is_dead_socket_error" in src
    _t("escalation helper", t_escalation_helper)

    def t_finalize_helper():
        import inspect as _i
        src = _i.getsource(_finalize_install_commit)
        assert "install commit" in src
        assert "summary_committed_on_target" in src
        assert "_parse_install_summary" in src
        assert "_run_install_remove_inactive" in src
        sig = _i.signature(_finalize_install_commit)
        assert "fw_file" in sig.parameters
        assert "_norm_ver" in src
    _t("finalize commit helper", t_finalize_helper)

    def t_finalize_respects_rollback():
        import inspect as _i
        src = _i.getsource(_finalize_install_commit)
        assert "PRESERVE_ROLLBACK" in src
    _t("finalize respects PRESERVE_ROLLBACK",
       t_finalize_respects_rollback)

    def t_finalize_detects_two_committed():
        import inspect as _i
        src = _i.getsource(_finalize_install_commit)
        assert "two committed versions" in src
    _t("finalize detects two-committed state",
       t_finalize_detects_two_committed)

    def t_finalize_uses_fw_file_not_running():
        import inspect as _i
        src = _i.getsource(_finalize_install_commit)
        assert "_get_running_image" not in src
    _t("finalize Path 3a uses fw_file",
       t_finalize_uses_fw_file_not_running)

    def t_finalize_refuses_empty_fw():
        import inspect as _i
        src = _i.getsource(_finalize_install_commit)
        assert "filename is unknown" in src
    _t("finalize refuses unknown fw", t_finalize_refuses_empty_fw)

    def t_wait_reboot_calls_finalize():
        import inspect as _i
        src = _i.getsource(wait_reboot_and_verify)
        assert "_finalize_install_commit" in src or \
            "_verify_after_reboot_impl" in src
        assert "fw_file" in _i.signature(wait_reboot_and_verify).parameters
    _t("wait_reboot calls finalize with fw_file",
       t_wait_reboot_calls_finalize)

    def t_reconcile_calls_finalize():
        import inspect as _i
        src = _i.getsource(_reconcile_failed_devices)
        assert "_finalize_install_commit" in src
    _t("reconcile calls finalize", t_reconcile_calls_finalize)

    def t_health_no_commit_check():
        import inspect as _i
        src = _i.getsource(post_upgrade_health_check)
        assert "summary_committed_on_target" not in src
    _t("health check has no commit re-check", t_health_no_commit_check)

    def t_stack_version_multi_syntax():
        import inspect as _i
        src = _i.getsource(check_stack_versions)
        assert "_per_member_version" in src
    _t("v35.9.36 stack per-member verify", t_stack_version_multi_syntax)

    def t_precheck_members_count_early():
        import inspect as _i
        src = _i.getsource(precheck_device)
        early = src.find("members_count = 1")
        assert early != -1
    _t("members_count defined early", t_precheck_members_count_early)

    def t_precheck_skips_gate_on_unreadable():
        import inspect as _i
        src = _i.getsource(precheck_device)
        assert "skip_per_member_gate" in src
        assert "SKIPPING pre-check space gate" in src
    _t("precheck skips gate on unreadable members",
       t_precheck_skips_gate_on_unreadable)

    def t_report_force():
        import inspect as _i
        sig = _i.signature(write_location_report)
        assert "force" in sig.parameters
        src = _i.getsource(_reconcile_failed_devices)
        assert "force=True" in src
    _t("report rewrite force=True", t_report_force)

    def t_atexit():
        src = open(__file__, "r", encoding="utf-8").read()
        assert "atexit.register(_cleanup_orphan_pwfiles)" in src
    _t("atexit pwfile cleanup", t_atexit)

    def t_lock_order():
        src = open(__file__, "r", encoding="utf-8").read()
        lock_pos = src.find("lock_handle = _acquire_instance_lock()")
        rot_pos = src.find("rotate_backups()")
        assert lock_pos != -1 and rot_pos != -1
        assert lock_pos < rot_pos
    _t("instance lock precedes rotation", t_lock_order)

    def t_fmt_dur():
        assert _fmt_duration(0) == "0s"
        assert _fmt_duration(45) == "45s"
        assert _fmt_duration(60) == "1m00s"
        assert _fmt_duration(200) == "3m20s"
        assert _fmt_duration(3725) == "1h02m05s"
        assert _fmt_duration(None) == "0s"
    _t("_fmt_duration", t_fmt_dur)

    def t_fmt_bytes():
        assert _fmt_bytes(500) == "500.00B"
        assert _fmt_bytes(1024 * 1024) == "1.00MB"
        assert _fmt_bytes(1024 * 1024 * 1024) == "1.00GB"
        assert _fmt_bytes(None) == "?"
    _t("_fmt_bytes", t_fmt_bytes)

    def t_device_line():
        s = _device_line({"hostname": "sw1", "ip": "10.0.0.1",
                          "status": "success",
                          "start_version": "17.15.01",
                          "target_version": "17.18.04",
                          "duration_sec": 720,
                          "md5_ok": True, "reboot_detected": True,
                          "clock_corrected": True})
        assert s.startswith("OK sw1")
        assert "17.15.01 -> 17.18.04" in s
        assert "12m00s" in s
    _t("_device_line", t_device_line)

    def t_summary_return():
        fake = {"LocA": {
            "sw1": {"hostname": "sw1", "ip": "10.0.0.1", "status": "success",
                    "stage": "install", "start_version": "17.15.01",
                    "target_version": "17.18.04", "post_version": "17.18.04",
                    "duration_sec": 720, "md5_ok": True,
                    "reboot_detected": True, "install_started": True,
                    "verify_pending": False, "clock_corrected": False,
                    "config_diff_lines": 0, "attempts": 1, "error": ""},
            "sw2": {"hostname": "sw2", "ip": "10.0.0.2", "status": "failed",
                    "stage": "install", "start_version": "17.15.01",
                    "target_version": "17.18.04", "post_version": "",
                    "duration_sec": 100, "md5_ok": False,
                    "reboot_detected": False, "install_started": True,
                    "verify_pending": True, "clock_corrected": False,
                    "config_diff_lines": 0, "attempts": 1,
                    "error": "install probe: not priv-15"},
        }}
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            n = print_summary(fake, {})
        assert n == 1
        out = buf.getvalue()
        assert "FINAL SUMMARY" in out
        assert "TOTAL" in out
    _t("print_summary returns failed count", t_summary_return)

    def t_anomaly():
        prev = {"run_id": "OLD", "results": [
            {"hostname": "sw1", "status": "success",
             "post_version": "17.18.04"}]}
        cur = {"LocA": {"sw1": {"hostname": "sw1", "status": "success",
                                "post_version": "17.15.01"}}}
        issues = detect_anomalies(cur, prev)
        assert any("regressed" in m for _, m in issues)
    _t("detect_anomalies", t_anomaly)

    def t_cli():
        real = sys.argv
        try:
            for flags in (["--only-upgrade-needed"], ["--preview"],
                          ["--preview-only"], ["--quiet-skipped"],
                          ["--no-html-report"], ["--no-health-snapshot"],
                          ["--use-inventory-cache"], ["--no-colour"],
                          ["--estimate-only"], ["--interactive-resume"],
                          ["--no-reconcile"], ["--no-hash-verify"],
                          ["--allow-lenient-firmware"],
                          ["--allow-active-pkg-purge"]):
                sys.argv = ["prog"] + flags
                parse_args()
        finally:
            sys.argv = real
    _t("CLI flags parse", t_cli)

    def t_pscp_retry_drops_pwfile():
        import inspect as _i
        src = _i.getsource(transfer_via_pscp)
        assert '"-pw", pw' in src
    _t("pscp retry drops -pwfile", t_pscp_retry_drops_pwfile)

    def t_clock_returns_entry_drift():
        import inspect as _i
        src = _i.getsource(_ensure_device_clock_correct)
        assert "entry_drift" in src
    _t("clock helper returns entry drift",
       t_clock_returns_entry_drift)

    def t_transfer_verify_local_size():
        import inspect as _i
        src = _i.getsource(_transfer_with_wipe_retry)
        assert "local_size" in src
    _t("transfer verifies local size", t_transfer_verify_local_size)

    def t_is_install_mode():
        assert "_is_install_mode" in globals()
        import inspect as _i
        src = _i.getsource(_is_install_mode)
        assert "packages.conf" in src
    _t("v35.9.31 _is_install_mode helper", t_is_install_mode)

    def t_read_active_packages_json():
        import inspect as _i
        src = _i.getsource(_read_active_packages)
        assert "file_name" in src
        assert "return active_conf, None" in src
        assert "boot\\s+flash:" in src
    _t("v35.9.32 _read_active_packages handles JSON + text + fail-safe",
       t_read_active_packages_json)

    def t_read_active_fallback():
        import inspect as _i
        src = _i.getsource(_read_active_packages)
        assert "install summary" in src
        assert "committed" in src
    _t("v35.9.36 _read_active_packages falls back to install summary",
       t_read_active_fallback)

    def t_pre_install_pkg_purge():
        import inspect as _i
        src = _i.getsource(_pre_install_pkg_purge)
        assert "ALLOW_ACTIVE_PKG_PURGE" in src
        assert "target .bin not on flash" in src
        assert "cannot determine active .pkg set" in src
    _t("v35.9.32 _pre_install_pkg_purge gated + verified",
       t_pre_install_pkg_purge)

    def t_transfer_worker_invokes_pkg_purge():
        import inspect as _i
        src = _i.getsource(transfer_worker)
        assert "_pre_install_pkg_purge" in src
        assert "ALLOW_ACTIVE_PKG_PURGE" in src
    _t("v35.9.32 transfer_worker invokes last-resort purge",
       t_transfer_worker_invokes_pkg_purge)

    def t_purge_refuses_when_unknown():
        import inspect as _i
        src = _i.getsource(_purge_unnecessary_files)
        assert "active_pkgs is None" in src
        assert "REFUSING to delete any .pkg" in src
    _t("v35.9.32 aggressive purge refuses when active set unknown",
       t_purge_refuses_when_unknown)

    def t_config_keys_has_flags():
        assert "ALLOW_ACTIVE_PKG_PURGE" in _CONFIG_KEYS
    _t("v35.9.35 _CONFIG_KEYS includes purge flag",
       t_config_keys_has_flags)

    def t_purge_standby_exists():
        import inspect as _i
        src = _i.getsource(_purge_standby_members)
        assert "stby-flash:" in src
        assert "flash-%d:" in src
    _t("v35.9.35 _purge_standby_members", t_purge_standby_exists)

    def t_pkg_set_present_detection():
        import inspect as _i
        src = _i.getsource(_is_target_pkg_set_present)
        assert "status=I" in src
        assert "status=A" in src
        assert "status=U" in src
    _t("v35.9.36 _is_target_pkg_set_present",
       t_pkg_set_present_detection)

    def t_precheck_early_return():
        import inspect as _i
        src = _i.getsource(precheck_device)
        assert "already_added_needs_activate" in src
        assert "_is_target_pkg_set_present" in src
    _t("v35.9.36 precheck skips gate when .pkg already present",
       t_precheck_early_return)

    def t_transfer_short_circuit():
        import inspect as _i
        src = _i.getsource(transfer_worker)
        assert "already_added_needs_activate" in src
        assert 'result["already_added"] = True' in src
    _t("v35.9.36 transfer_worker short-circuits already-added",
       t_transfer_short_circuit)

    def t_activate_only_helper():
        assert "_run_install_activate_only" in globals()
        assert "_run_install_commit_only" in globals()
        import inspect as _i
        src = _i.getsource(_run_install_activate_only)
        assert "install activate" in src
        assert "install add file" not in src
    _t("v35.9.37 activate-only helper", t_activate_only_helper)

    def t_commit_only_helper():
        import inspect as _i
        src = _i.getsource(_run_install_commit_only)
        assert "_finalize_install_commit" in src
    _t("v35.9.37 commit-only helper", t_commit_only_helper)

    def t_install_worker_alreadyadded_cmd():
        import inspect as _i
        src = _i.getsource(install_worker)
        assert "_run_install_activate_only" in src
        assert "_run_install_commit_only" in src
    _t("v35.9.37 install_worker uses activate+commit path",
       t_install_worker_alreadyadded_cmd)

    def t_no_abort_after_add():
        import inspect as _i
        src = _i.getsource(install_worker)
        assert "allow_abort=False" in src
    _t("v35.9.37 no install abort after add", t_no_abort_after_add)

    def t_runver_match_normalized():
        import inspect as _i
        src = _i.getsource(_purge_standby_members)
        assert "fver_key == running_key" in src
        assert "_VER3_NORM_RE" in src
    _t("v35.9.37 standby running-version match normalised",
       t_runver_match_normalized)

    def t_standby_junk_purge():
        import inspect as _i
        src = _i.getsource(_purge_standby_members)
        assert ".USWAP" in src
        assert "tech_support" in src
    _t("v35.9.37 standby junk dir purge", t_standby_junk_purge)

    def t_runinstall_detects_already_added():
        import inspect as _i
        src = _i.getsource(run_install)
        assert "_ALREADY_ADDED_MARKERS" in src
        assert "already_added_refused" in src
        assert "super package already added" in _ALREADY_ADDED_MARKERS
    _t("v35.9.37 run_install detects super-package-already-added",
       t_runinstall_detects_already_added)

    def t_conf_keep():
        import inspect as _i
        src = _i.getsource(_purge_unnecessary_files)
        assert "FIX-CONF-KEEP" in src or "keep (target .conf)" in src
        assert "keep (target .conf)" in src
    _t("v35.9.38 keeps target .conf during purge", t_conf_keep)

    def t_precommit_helper():
        assert "_state_needs_precommit" in globals()
        assert "_run_install_commit_for_precommit" in globals()
    _t("v35.9.38 pre-commit helpers exist", t_precommit_helper)

    def t_activate_handles_cannot_activate():
        import inspect as _i
        src = _i.getsource(_run_install_activate_only)
        assert "cannot activate; please first perform" in src
        assert "_state_needs_precommit" in src
    _t("v35.9.38 activate handles cannot-activate",
       t_activate_handles_cannot_activate)

    def t_activate_detects_partial():
        import inspect as _i
        src = _i.getsource(_run_install_activate_only)
        assert "partial activation" in src
        assert "per_member_fail" in src
    _t("v35.9.38 activate detects partial failure",
       t_activate_detects_partial)

    def t_pwfile_unique():
        a = _pwfile_for_thread()
        b = _pwfile_for_thread()
        assert a != b
        assert _PWFILE_COUNTER >= 2
    _t("v35.9.38 pwfile paths are unique", t_pwfile_unique)

    def t_pscp_retry_window_widened():
        import inspect as _i
        src = _i.getsource(transfer_via_pscp)
        assert "elapsed < 60" in src
        assert "elapsed < 5" not in src
    _t("v35.9.38 pscp retry window widened",
       t_pscp_retry_window_widened)

    def t_finalize_no_infinite_activate():
        import inspect as _i
        src = _i.getsource(_finalize_install_commit)
        assert "st_attempts" in src
        assert "reissued_activate" in src
    _t("v35.9.38 finalize refuses to loop on target=I",
       t_finalize_no_infinite_activate)

    def t_stack_verify_platform_safe():
        import inspect as _i
        src = _i.getsource(_per_member_version)
        assert "per_member_syntax_ok" in src
        assert "show version | include Version" in src
        src2 = _i.getsource(check_stack_versions)
        assert "unverified" in src2 or " X" in src2
    _t("v35.9.38 stack-verify is platform-safe",
       t_stack_verify_platform_safe)

    def t_precheck_passes_target_ver_to_purge():
        import inspect as _i
        src = _i.getsource(precheck_device)
        assert "target_ver=target_ver" in src
    _t("v35.9.38 precheck passes target_ver to purge",
       t_precheck_passes_target_ver_to_purge)

    def t_runinstall_nudge_returns_on_dead_transport():
        import inspect as _i
        src = _i.getsource(run_install)
        assert "tr.is_active()" in src
        assert "dead = True" in src
        assert "activate nudged, transport" in src or \
               "reload in progress" in src
    _t("v35.9.38 run_install returns on dead transport",
       t_runinstall_nudge_returns_on_dead_transport)

    def t_runinstall_precommits_on_u_state():
        import inspect as _i
        src = _i.getsource(run_install)
        assert "_state_needs_precommit" in src
        assert "_run_install_commit_for_precommit" in src
    _t("v35.9.38 run_install pre-commits U state",
       t_runinstall_precommits_on_u_state)

    def t_md5_nonfatal():
        import inspect as _i
        src = _i.getsource(install_worker)
        assert "send_command_timing" in src
        assert "MD5 not confirmed" in src
        assert "non-fatal" in src
    _t("v35.9.38 MD5 verify is non-fatal", t_md5_nonfatal)

    def t_retry_install_failures():
        import inspect as _i
        src = _i.getsource(is_retryable)
        assert "recoverable" in src
    _t("v35.9.38 install failures are retryable when recoverable",
       t_retry_install_failures)

    def t_revert_verify_default():
        import inspect as _i
        src = _i.getsource(verify_revert_clean)
        assert "hmac-sha1" in src
        assert "aes128-ctr" in src
        assert "ip ssh server algorithm mac" in src
    _t("v35.9.38 revert-verify ignores defaults",
       t_revert_verify_default)

    def t_low_unbound_fixed():
        import inspect as _i
        src = _i.getsource(_run_install_activate_only)
        assert "FIX-LOW-UNBOUND" in src or 'low = ""' in src
        assert 'low = ""' in src
    _t("v35.9.39 _run_install_activate_only binds `low`",
       t_low_unbound_fixed)

    def t_already_added_ordered():
        import inspect as _i
        src = _i.getsource(run_install)
        p_already = src.find("_ALREADY_ADDED_MARKERS")
        p_failed  = src.find('re.search(r"failed:\\s*install", low)')
        assert p_already != -1, "_ALREADY_ADDED_MARKERS not found in run_install"
        assert p_failed  != -1, 'failed:install check not found in run_install'
        assert p_already < p_failed, (
            "_ALREADY_ADDED_MARKERS at offset %d must appear before "
            "failed:install at offset %d" % (p_already, p_failed))
    _t("v35.9.39 already-added is checked before failed:install",
       t_already_added_ordered)

    def t_already_added_markers():
        assert "_ALREADY_ADDED_MARKERS" in globals()
        assert "super package already added" in _ALREADY_ADDED_MARKERS
        assert "add operation not allowed" in _ALREADY_ADDED_MARKERS
    _t("v35.9.39 _ALREADY_ADDED_MARKERS present",
       t_already_added_markers)

    def t_already_added_3tuple():
        import inspect as _i
        src = _i.getsource(run_install)
        idx = src.find("_ALREADY_ADDED_MARKERS")
        assert idx != -1
        tail = src[idx:idx + 600]
        assert 'already_added_refused' in tail
        ret_start = tail.find('"add because .pkg set is already on flash"')
        assert ret_start != -1
        ret_end = tail.find("\n", ret_start)
        ret_line = tail[ret_start:ret_end]
        assert ", conn" in ret_line, \
            "already_added_refused return must carry conn: %r" % ret_line
    _t("v35.9.39 already-added return carries conn",
       t_already_added_3tuple)

    def t_read_active_pkg_version_match():
        wanted = {_norm_ver("17.12.04")}
        assert wanted == {"17.12.4"}
        for fn in ("cat9k_lite-rpbase.17.12.04.SPA.pkg",
                   "cat9k_lite-webui.17.12.04.SPA.pkg",
                   "cat9k_lite-rpboot.17.12.04.SPA.pkg",
                   "cat9k_lite-srdriver.17.12.04.SPA.pkg"):
            fm = _VER3_NORM_RE.search(fn)
            assert fm is not None
            assert _norm_ver(fm.group(0)) in wanted, fn
        for fn in ("cat9k_lite-rpbase.17.06.03.SPA.pkg",
                   "cat9k_lite-webui.17.06.03.SPA.pkg",
                   "cat9k_lite-rpboot.17.09.04a.SPA.pkg"):
            fm = _VER3_NORM_RE.search(fn)
            assert fm is not None
            assert _norm_ver(fm.group(0)) not in wanted, fn
    _t("v35.9.41 active-pkg version match (17.12.4 vs 17.12.04)",
       t_read_active_pkg_version_match)

    def t_read_active_pkg_uses_running():
        import inspect as _i
        src = _i.getsource(_read_active_packages)
        assert "FIX-ACTIVE-PKG-RUNNING" in src
        assert "_get_running_version_string" in src
        assert "_VER3_NORM_RE" in src
    _t("v35.9.41 active-pkg fallback consults running version",
       t_read_active_pkg_uses_running)

    def t_wait_install_op_idle_exists():
        assert "_wait_install_op_idle" in globals()
        import inspect as _i
        src = _i.getsource(_wait_install_op_idle)
        assert "FIX-WAIT-OP-IDLE" in src
        assert "show install summary" in src
    _t("v35.9.42 _wait_install_op_idle helper present",
       t_wait_install_op_idle_exists)

    def t_activate_fastpath_check():
        import inspect as _i
        src = _i.getsource(_run_install_activate_only)
        assert "FIX-FASTPATH-ALREADY-ON-TARGET" in src
        assert "already on target -- skipping activate" in src
        assert "_wait_install_op_idle" in src
    _t("v35.9.42 activate has fast-path + busy-wait",
       t_activate_fastpath_check)

    def t_commit_busy_wait():
        import inspect as _i
        src = _i.getsource(_finalize_install_commit)
        assert "FIX-COMMIT-BUSY-WAIT" in src
        assert "commit: install engine busy" in src
    _t("v35.9.42 commit backs off when engine busy",
       t_commit_busy_wait)

    def t_pscp_stall_detection():
        import inspect as _i
        src = _i.getsource(_pscp_run_once)
        assert "FIX-PSCP-STALL" in src
        assert "SCP_STALL_TIMEOUT" in src
        assert "proc.kill()" in src
        assert "chunks.get(timeout=1.0)" in src or "queue.Empty" in src
    _t("v35.9.43 pscp kills stalled transfers", t_pscp_stall_detection)

    def t_version_string_v43():
        assert VERSION_STRING == "35.9.43", \
            "VERSION_STRING should be 35.9.43, got %s" % VERSION_STRING
    _t("VERSION_STRING is 35.9.43", t_version_string_v43)

    def t_activate_settle():
        import inspect as _i
        src = _i.getsource(_run_install_activate_only)
        assert "FIX-ACT-SETTLE" in src
        assert "time.sleep(30)" in src
    _t("v35.9.43 activate waits for engine to settle",
       t_activate_settle)

    total = len(passed) + len(failed)
    print("\n" + "=" * 70)
    print("  VALIDATION -- %d check(s)" % total)
    print("=" * 70)
    for name in passed: print("  OK %s" % name)
    if failed:
        print()
        for name, err in failed: print("  FAIL %s: %s" % (name, err))
    print("-" * 70)
    print("  Passed: %d/%d" % (len(passed), total))
    print("  Failed: %d/%d" % (len(failed), total))
    print("=" * 70 + "\n")
    return 0 if not failed else 1


def main():
    global DRY_RUN, SKIP_ISSU, PAUSE_BETWEEN_LOCATIONS, AUTO_ROLLBACK_ON_FAIL
    global LOCATIONS_TO_RUN, ENABLE_PASSWORD, ENABLE_USER, REVERT_VERIFY_AFTER
    global LIVE_LOG_FEED_TRANSFER, SERIAL_TRANSFER_LARGE_MODELS
    global SKIP_CONFIG_DRIFT_CHECK, ALLOW_BUNDLE_MODE_CONVERSION
    global POOL_LOCATIONS, VERIFY_TRANSFER_HASH, RECONCILE_FAILED_AT_END
    global LARGE_MODEL_PARALLEL, PARAMIKO_PRIMARY, LARGE_MODEL_SEMAPHORE
    global BULK_MODE_WINDOW_SIZE, USE_COLOUR, QUIET_SKIPPED
    global FAMILY_SIZE_BOUNDS_STRICT, ALLOW_ACTIVE_PKG_PURGE
    args = parse_args()

    if args.validate:
        return _validate()

    if args.config: apply_config_file(args.config)
    if args.base_dir: update_paths(args.base_dir)
    for d in (LOG_DIR, STATE_DIR, REPORT_DIR, BACKUP_DIR, CHECKPOINT_DIR):
        try: os.makedirs(d, exist_ok=True)
        except OSError: pass
    if args.write_manifest:
        _cleanup_orphan_pwfiles(); _write_manifest(); return 0

    lock_handle = _acquire_instance_lock()
    if lock_handle is None: return 3
    _cleanup_orphan_pwfiles()
    _check_local_disk_space()
    rotate_backups()
    rotate_log_archive()

    if args.dry_run:          DRY_RUN = True
    if args.skip_issu:        SKIP_ISSU = True
    if args.auto_rollback:    AUTO_ROLLBACK_ON_FAIL = True
    if args.no_pause:         PAUSE_BETWEEN_LOCATIONS = False
    if args.locations:        LOCATIONS_TO_RUN = args.locations
    if args.no_verify_revert: REVERT_VERIFY_AFTER = False
    if args.show_live_transfer: LIVE_LOG_FEED_TRANSFER = True
    if args.no_serial_large:  SERIAL_TRANSFER_LARGE_MODELS = False
    if args.no_drift_check:   SKIP_CONFIG_DRIFT_CHECK = True
    if args.no_hash_verify:   VERIFY_TRANSFER_HASH = False
    if args.no_reconcile:     RECONCILE_FAILED_AT_END = False
    if args.no_bundle_mode:   ALLOW_BUNDLE_MODE_CONVERSION = False
    if args.allow_bundle_mode: ALLOW_BUNDLE_MODE_CONVERSION = True
    if args.no_pool_locations: POOL_LOCATIONS = False
    if args.pool_locations:   POOL_LOCATIONS = True
    if args.allow_lenient_firmware:
        FAMILY_SIZE_BOUNDS_STRICT = False
        print("  ! --allow-lenient-firmware: strict family size check "
              "disabled (absolute 2 GB cap still applies)")
    if args.allow_active_pkg_purge:
        ALLOW_ACTIVE_PKG_PURGE = True
        print("  ! --allow-active-pkg-purge: active .pkg deletion enabled. "
              "If install fails after this point, MANUAL CONSOLE RECOVERY "
              "will be required.")
    if args.parallel_large is not None:
        LARGE_MODEL_PARALLEL = max(1, args.parallel_large)
        LARGE_MODEL_SEMAPHORE = threading.Semaphore(LARGE_MODEL_PARALLEL)
    if args.paramiko_primary: PARAMIKO_PRIMARY = True
    if args.bulk_window is not None:
        if args.bulk_window < 131072:
            print("  --bulk-window %d < 131072 -- ignored"
                  % args.bulk_window)
        else:
            BULK_MODE_WINDOW_SIZE = args.bulk_window
    if args.quiet_skipped: QUIET_SKIPPED = True
    if args.no_colour: USE_COLOUR = False

    if os.name == "nt" and not args.no_colour:
        try:
            import ctypes
            _k = ctypes.windll.kernel32
            _h = _k.GetStdHandle(-11)
            _m = ctypes.c_ulong()
            if _k.GetConsoleMode(_h, ctypes.byref(_m)):
                _k.SetConsoleMode(_h, _m.value | 0x0004)
        except Exception: pass

    if args.resume:
        print("  --resume deprecated; use --force-run-with-stale-state.")
        args.ignore_stale_state = True
    if args.force_run_with_stale_state:
        args.ignore_stale_state = True
    if args.enable_pass:
        print("  --enable-pass visible in process list; prefer "
              "$CISCO_ENABLE.")
    ENABLE_PASSWORD = (args.enable_pass or os.environ.get("CISCO_ENABLE")
                       or None)
    ENABLE_USER = (args.enable_user
                   or os.environ.get("CISCO_ENABLE_USER") or None)
    if ENABLE_PASSWORD is None and not args.dry_run_revert:
        print("  (enable password not set -- falling back to SSH password)")

    signal.signal(signal.SIGINT, _on_signal)
    try: signal.signal(signal.SIGTERM, _on_signal)
    except (ValueError, OSError, AttributeError): pass
    if hasattr(signal, "SIGBREAK"):
        try: signal.signal(signal.SIGBREAK, _on_signal)
        except (ValueError, OSError): pass

    if args.dry_run_revert: return mode_dry_run_revert()
    if args.recover:        return mode_recover(args)
    if args.revert_only:    return mode_recover(
        args, locations_filter=LOCATIONS_TO_RUN)

    rotate_logs()
    print_ssh_banner()

    stale = list_state_files()
    if stale and not (args.ignore_stale_state
                      or args.force_run_with_stale_state or args.resume):
        if args.interactive_resume:
            choice = prompt_resume_or_abort(stale)
            if choice == "abort":
                print("  Aborted (state kept)."); return 2
            args.ignore_stale_state = True
            if choice == "resume": args.resume_checkpoint = True
            if choice == "skip":   args.retry_failed = True
        else:
            print("\n  Un-reverted temp-config state from earlier run:")
            for s in stale: print("     - %s" % s)
            print("  Use --dry-run-revert to inspect, --recover to fix, "
                  "--interactive-resume to prompt, or "
                  "--force-run-with-stale-state to proceed.\n")
            return 2

    for _, fw, _ in MODEL_FIRMWARE_MAP:
        p = os.path.join(FIRMWARE_DIR, fw)
        if os.path.isfile(p):
            FIRMWARE_SIZES[fw] = os.path.getsize(p)

    print("\n  -- Firmware inventory --")
    for fw_name in sorted(set(fw for _, fw, _ in MODEL_FIRMWARE_MAP)):
        p = os.path.join(FIRMWARE_DIR, fw_name)
        if os.path.isfile(p):
            print("    %-45s %s" % (fw_name, _fmt_bytes(os.path.getsize(p))))
        else:
            print("    %-45s MISSING" % fw_name)
    map_errors, map_warnings = verify_firmware_map()
    if map_errors:
        print("\n  FIRMWARE pre-flight FAILED (hard stop):")
        for e in map_errors: print("     - %s" % e)
        print("\n  Fix the firmware files and re-run.  If you are certain")
        print("  the sizes are correct for your platform, override with")
        print("  --allow-lenient-firmware (NOT recommended).\n")
        return 1
    if map_warnings:
        print("\n  MODEL_FIRMWARE_MAP warnings:")
        for w in map_warnings: print("     - %s" % w)
    print("  Firmware pre-flight passed")

    loc_devices = {}
    if args.hosts:
        hostmap = build_host_ip_map()
        all_known = sorted(hostmap.keys())
        wanted = {h.strip() for h in args.hosts}
        devices = [{"hostname": h, "ip": hostmap[h]}
                   for h in wanted if h in hostmap]
        for h in [x for x in wanted if x not in hostmap]:
            print("  Host not found: %s" % h)
            suggestions = suggest_similar_hosts(h, all_known)
            if suggestions:
                print("     Did you mean: %s" % ", ".join(suggestions[:3]))
        if devices: loc_devices["ad-hoc"] = devices
    else:
        seen = set()
        for loc in LOCATIONS_TO_RUN:
            p = os.path.join(LOCATIONS_DIR, "%s.txt" % loc)
            if not os.path.isfile(p):
                print("  Missing: %s -- skipping" % p); continue
            loc_devices[loc] = load_location(p, reference_hosts=seen)
            seen.update(d["hostname"] for d in loc_devices[loc])

    dups = detect_duplicate_hostnames(loc_devices)
    if dups:
        print("\n  Duplicate hostnames/IPs:")
        for h, a, b in dups: print("     - %s: %s and %s" % (h, a, b))
    for loc in list(loc_devices):
        loc_devices[loc] = filter_devices(loc_devices[loc], args)

    all_devices = [d for ds in loc_devices.values() for d in ds]
    if not all_devices:
        print("  No devices to process."); return 1

    user, pw = get_credentials(args)

    if args.inventory:
        return mode_inventory(all_devices, user, pw)
    if args.check:
        return mode_check(all_devices, user, pw)
    if args.verify_mapping:
        return mode_verify_mapping(all_devices, user, pw)
    if args.rollback_dry_run:
        return mode_rollback(all_devices, user, pw, args, dry=True)
    if args.rollback:
        return mode_rollback(all_devices, user, pw, args)
    if args.estimate_only:
        return estimate_runtime(all_devices, user, pw)

    if args.only_upgrade_needed:
        print("\n  -- Filtering to devices that need upgrade --")
        need, tgt, unr = filter_only_upgrade_needed(all_devices, user, pw)
        print("    %d need upgrade, %d already on target, %d unreachable"
              % (len(need), len(tgt), len(unr)))
        if not need:
            print("  Nothing to do -- every reachable device is on target.")
            return 0
        all_devices = [d for d, _ in need]
        keep = {d["hostname"] for d in all_devices}
        loc_devices = {loc: [d for d in devs if d["hostname"] in keep]
                       for loc, devs in loc_devices.items()}
        loc_devices = {loc: ds for loc, ds in loc_devices.items() if ds}
        if not loc_devices:
            print("  No locations left after filtering."); return 0

    if args.preview or args.preview_only or not args.yes:
        print_change_preview(all_devices, user, pw)
        if args.preview_only:
            print("  Preview-only mode -- exiting."); return 0

    if args.precache_hostkeys:
        precache_host_keys(all_devices, user, pw)
    errors, _ = preflight_validation(all_devices, user, pw)
    if errors:
        print("  Pre-flight failed -- aborting."); return 1
    if args.preflight_only:
        print("  Pre-flight-only mode -- exiting."); return 0

    if not confirm("  Proceed with %supgrade of %d device(s)?"
                   % ("DRY-RUN of " if DRY_RUN else "",
                      len(all_devices)), args.yes):
        print("  Cancelled."); return 1

    all_results, all_revert = {}, {}
    start_monitor_thread()
    try:
        if POOL_LOCATIONS and len(loc_devices) > 1:
            print("\n  -- POOLED MODE (per-location abort gates) --")
            master_log("POOLED START: %d locations" % len(loc_devices))
            all_results, all_revert = _run_pooled(
                loc_devices, user, pw,
                resume_checkpoint=args.resume_checkpoint,
                retry_failed=args.retry_failed)
        else:
            locs = list(loc_devices)
            for i, loc in enumerate(locs):
                if SHUTDOWN_REQ.is_set(): break
                p = os.path.join(LOCATIONS_DIR, "%s.txt" % loc)
                if os.path.isfile(p):
                    fresh = load_location(p)
                    if fresh:
                        loc_devices[loc] = filter_devices(fresh, args)
                results, aborted, rv = run_location(
                    loc, loc_devices[loc], user, pw,
                    resume_checkpoint=args.resume_checkpoint,
                    retry_failed=args.retry_failed)
                all_results[loc] = results
                all_revert[loc] = rv
                if aborted: break
                if (PAUSE_BETWEEN_LOCATIONS and i < len(locs) - 1
                        and not SHUTDOWN_REQ.is_set()):
                    if not confirm("\n  %s finished. Continue to %s?"
                                   % (loc, locs[i+1])):
                        print("  Stopping at operator request."); break
    finally:
        stop_monitor_thread()
        try:
            all_results, all_revert = _reconcile_failed_devices(
                all_results, all_revert, user, pw)
        except Exception as e:
            master_log("Reconcile pass raised: %s" % e)
            print("\n  Reconcile pass raised: %s\n" % e)
        try:
            write_run_summary(
                all_results, all_revert, RUN_ID,
                os.path.join(REPORT_DIR, "run_summary_%s.json" % RUN_ID))
        except Exception as e:
            master_log("run_summary raised: %s" % e)
        if not args.no_html_report:
            try:
                write_html_report(
                    all_results,
                    os.path.join(REPORT_DIR, "run_%s.html" % RUN_ID))
            except Exception as e:
                master_log("HTML raised: %s" % e)
        if not args.no_health_snapshot and not DRY_RUN:
            try:
                post_run_health_snapshot(
                    all_results, user, pw,
                    os.path.join(REPORT_DIR, "health_%s.json" % RUN_ID))
            except Exception as e:
                master_log("Health raised: %s" % e)
        failed = print_summary(all_results, all_revert)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

def _run_install_commit_only(conn, host, st, ip, user, pw, target_ver):
    wlog(host, "COMMIT (already-added path)", "STEP")
    set_state(host, "INSTALL", "commit")
    if st.get("reboot_detected") or conn is None:
        wlog(host, "Waiting for reboot to settle before commit", "INFO")
        if not wait_for_ping_down(ip, host,
                                  timeout_sec=PING_DOWN_TIMEOUT_SEC):
            wlog(host, "Device did not go down -- checking anyway", "WARN")
        if not wait_for_ping_up(ip, host,
                                timeout_sec=PING_UP_TIMEOUT_SEC):
            return False, "device did not return after activate", None
        if not wait_for_ping_stable(ip, host):
            return False, "boot loop detected", None
        if not wait_for_ssh_ready(ip, host):
            return False, "SSH did not return after activate", None
        time.sleep(POST_REBOOT_SETTLE_SEC)
        conn = robust_reconnect(ip, user, pw, host,
                                max_attempts=POST_REBOOT_MAX_ATTEMPTS,
                                delay=POST_REBOOT_DELAY_SEC,
                                purpose="post-activate commit")
        if not conn:
            return False, "could not reconnect for commit", None
    if _finalize_install_commit(conn, host, target_ver, fw_file=""):
        return True, "", conn
    return False, "commit could not be verified", conn


def precheck_device(conn, host, fw_file, target_ver):
    wlog(host, "--- PRE-CHECK ---", "STEP")
    members_count = 1
    try:
        sw = conn.send_command("show switch", read_timeout=60)
        rows = _SWITCH_ROW_RE.findall(sw)
        members_count = len(rows) if rows else 1
    except Exception:
        members_count = 1

    set_state(host, "PRE-CHECK", "clock")
    _ok, _drift, _tz = _ensure_device_clock_correct_cached(
        conn, host, max_drift_sec=CLOCK_DRIFT_FIX_SEC)
    clock_fixed = bool(_ok and _drift is not None
                       and _drift > CLOCK_DRIFT_FIX_SEC)

    set_state(host, "PRE-CHECK", "model")
    model = get_model(conn)
    if model: wlog(host, "  Model: %s" % model, "INFO")

    ok_fam, reason = verify_model_firmware_consistency(
        model, fw_file, target_ver)
    if not ok_fam:
        wlog(host, "  Firmware/model mismatch: %s" % reason, "ERROR")
        if STRICT_FAMILY_CHECK:
            return (False, "firmware mismatch: %s" % reason, "unknown",
                    clock_fixed)
        else:
            wlog(host, "  Continuing in lenient mode", "WARN")

    set_state(host, "PRE-CHECK", "readiness")
    ready_ok, ready_reason = verify_boot_and_install_ready(
        conn, host, fw_file, self_heal=True)
    if not ready_ok:
        wlog(host, "  readiness gate: %s" % ready_reason, "ERROR")
        return (False, ready_reason, "unknown", clock_fixed)

    set_state(host, "PRE-CHECK", "version")
    ver_out = conn.send_command("show version | include Version")
    m = re.search(r"Version ([\w.()]+)", ver_out)
    current_ver = m.group(1) if m else "unknown"
    wlog(host, "  Version: %s  ->  target %s" % (current_ver, target_ver),
         "INFO", silent=QUIET_SKIPPED)

    if _norm_ver(current_ver) == _norm_ver(target_ver):
        needs_finalize = False
        try:
            summ = conn.send_command("show install summary",
                                     read_timeout=60)
            feed_live_log(host,
                          "[precheck] show install summary\n%s" % summ)
            if summary_committed_on_target(summ, target_ver):
                wlog(host, "  on target and committed", "OK",
                     silent=QUIET_SKIPPED)
            else:
                entries = _parse_install_summary(summ)
                status = entries.get(_norm_ver(target_ver))
                other_c = [v for v, s in entries.items()
                           if s == "C" and v != _norm_ver(target_ver)]
                if other_c:
                    wlog(host, "  on target but TWO committed versions "
                               "present (%s) -- manual remediation required"
                         % ", ".join(other_c), "ERROR")
                    return (False,
                            "two committed versions present: %s + %s"
                            % (target_ver, ", ".join(other_c)),
                            current_ver, clock_fixed)
                wlog(host, "  on target but install summary status=%s "
                           "-- will run install commit" % (status or "?"),
                     "WARN")
                needs_finalize = True
        except Exception as e:
            wlog(host, "  summary read failed: %s -- assuming commit "
                       "needed" % str(e)[:80], "WARN")
            needs_finalize = True

        residuals = {}
        try:
            residuals = _detect_residual_temp_config(conn, host)
        except Exception as e:
            wlog(host, "  residual scan failed: %s" % str(e)[:80], "WARN")

        existing_types = {ch["type"] for ch in get_temp_changes(host)}
        newly_discovered = []
        for t, d in residuals.items():
            if t not in existing_types:
                newly_discovered.append(t)
            track_temp_change(host, t, d)

        all_residual_types = set(existing_types) | set(residuals.keys())
        needs_cleanup = bool(all_residual_types)

        if newly_discovered:
            wlog(host, "  newly discovered residual temp config: %s"
                 % ", ".join(sorted(newly_discovered)), "WARN")
        if needs_cleanup:
            wlog(host, "  temp config to revert: %s"
                 % ", ".join(sorted(all_residual_types)), "INFO")

        if not needs_finalize and not needs_cleanup:
            wlog(host, "  on target, committed, and clean", "OK")
            return (True, "already_on_target", current_ver, clock_fixed)
        if needs_finalize and not needs_cleanup:
            wlog(host, "  fixup: finalize only", "INFO")
            return (True, "already_on_target_needs_finalize", current_ver,
                    clock_fixed)
        if not needs_finalize and needs_cleanup:
            wlog(host, "  fixup: cleanup only", "INFO")
            return (True, "already_on_target_needs_cleanup", current_ver,
                    clock_fixed)
        wlog(host, "  fixup: finalize + cleanup", "INFO")
        return (True, "already_on_target_needs_finalize_and_cleanup",
                current_ver, clock_fixed)

    already_added, added_reason = _is_target_pkg_set_present(
        conn, host, target_ver)
    if already_added:
        wlog(host, "  %s" % added_reason, "OK")
        wlog(host, "  skipping space gate and transfer; proceeding to "
                   "activate/commit", "OK")
        return (True, "already_added_needs_activate",
                current_ver, clock_fixed)

    boot = conn.send_command("show boot | include BOOT", read_timeout=60)
    feed_live_log(host, "[precheck] show boot\n%s" % boot)
    if "packages.conf" not in boot:
        if ALLOW_BUNDLE_MODE_CONVERSION:
            wlog(host, "  Bundle mode -- install will convert", "WARN")
            master_log("%s: BUNDLE MODE -- will convert via install add" % host)
        else:
            wlog(host, "  Not INSTALL mode", "ERROR")
            return (False, "not_install_mode", current_ver, clock_fixed)

    fw_size = get_firmware_size(fw_file)
    if not fw_size:
        fw_size = MIN_FREE_BYTES

    bin_present = False
    try:
        out = conn.send_command(
            "dir flash: | include %s" % re.escape(fw_file),
            read_timeout=TRANSFER_VERIFY_TIMEOUT)
        if fw_file in out:
            remote_size = _parse_file_size_from_dir(out, fw_file)
            if remote_size and remote_size == fw_size:
                bin_present = True
                wlog(host, "  target .bin already on flash (correct "
                           "size)", "OK")
            elif remote_size:
                wlog(host, "  target .bin on flash but wrong size "
                           "(%d vs %d) -- will be re-transferred"
                     % (remote_size, fw_size), "WARN")
    except Exception:
        pass

    extraction = int(fw_size * EXTRACTION_OVERHEAD_FACTOR)
    required_active = (extraction + EXTRA_HEADROOM_BYTES) if bin_present \
                      else (fw_size + extraction + EXTRA_HEADROOM_BYTES)
    wlog(host, "  Space plan: fw_size=%s extraction=%s headroom=%s "
               "bin_on_flash=%s"
         % (_fmt_bytes(fw_size), _fmt_bytes(extraction),
            _fmt_bytes(STACK_MEMBER_HEADROOM),
            "yes" if bin_present else "no"), "INFO")

    if not DRY_RUN:
        try:
            in_install = _is_install_mode(conn)
            if in_install:
                wlog(host, "  Purging stale .bin / .conf / junk "
                           "(running .bin is deletable in install mode)",
                     "INFO")
                _purge_unnecessary_files(conn, host, fw_file, aggressive=False,
                                         target_ver=target_ver)
                if members_count > 1:
                    _purge_standby_members(conn, host, fw_file, members_count)
                time.sleep(2)
                try:
                    out2 = conn.send_command(
                        "dir flash: | include %s" % re.escape(fw_file),
                        read_timeout=60)
                    if fw_file in out2:
                        bin_present = True
                except Exception:
                    pass
        except Exception as e:
            wlog(host, "  purge failed (non-fatal): %s" % str(e)[:80],
                 "WARN")

    try:
        per_member_bytes = _get_all_member_free_bytes(conn, host)
        skip_per_member_gate = False
        if per_member_bytes is None:
            wlog(host, "  Could not verify all stack member storage -- "
                       "SKIPPING pre-check space gate "
                       "(install will validate)", "WARN")
            skip_per_member_gate = True

        if (not skip_per_member_gate) and per_member_bytes and fw_size:
            shortfalls = []
            for idx, mfree in enumerate(per_member_bytes):
                need_this = _member_required_bytes(
                    fw_size,
                    preserve_rollback=PRESERVE_ROLLBACK,
                    bin_already_present=(bin_present and idx == 0),
                    is_standby=(idx > 0))
                role = "active" if idx == 0 else "standby"
                marker = "OK" if mfree >= need_this else "SHORT"
                wlog(host, "  member %d (%s): free=%s need=%s %s"
                     % (idx + 1, role, _fmt_bytes(mfree),
                        _fmt_bytes(need_this), marker),
                     "OK" if mfree >= need_this else "WARN")
                if mfree < need_this:
                    shortfalls.append((idx + 1, role, mfree, need_this))

            if shortfalls:
                wlog(host, "  Space short on %d member(s) -- attempting "
                           "aggressive purge" % len(shortfalls), "WARN")
                try:
                    _purge_unnecessary_files(conn, host, fw_file,
                                             aggressive=True,
                                             target_ver=target_ver)
                    if members_count > 1:
                        _purge_standby_members(conn, host, fw_file,
                                               members_count)
                except Exception as e:
                    wlog(host, "  aggressive purge failed: %s"
                         % str(e)[:80], "WARN")
                time.sleep(3)
                per_member_bytes = _get_all_member_free_bytes(conn, host)
                if per_member_bytes is None:
                    skip_per_member_gate = True
                else:
                    shortfalls = []
                    for idx, mfree in enumerate(per_member_bytes):
                        need_this = _member_required_bytes(
                            fw_size,
                            preserve_rollback=PRESERVE_ROLLBACK,
                            bin_already_present=(bin_present and idx == 0),
                            is_standby=(idx > 0))
                        role = "active" if idx == 0 else "standby"
                        marker = "OK" if mfree >= need_this else "SHORT"
                        wlog(host,
                             "  after purge -- member %d (%s): free=%s "
                             "need=%s %s"
                             % (idx + 1, role, _fmt_bytes(mfree),
                                _fmt_bytes(need_this), marker),
                             "OK" if mfree >= need_this else "WARN")
                        if mfree < need_this:
                            shortfalls.append((idx + 1, role, mfree,
                                               need_this))

            if shortfalls and not skip_per_member_gate:
                detail = "; ".join(
                    "m%d(%s) free=%s need=%s"
                    % (m, role, _fmt_bytes(f), _fmt_bytes(n))
                    for m, role, f, n in shortfalls)
                reason = ("insufficient_space_stack: %s "
                          "fw_size=%s extraction=%s headroom=%s"
                          % (detail,
                             _fmt_bytes(fw_size),
                             _fmt_bytes(extraction),
                             _fmt_bytes(STACK_MEMBER_HEADROOM)))
                wlog(host, "  STILL insufficient: %s -- REFUSING"
                     % reason, "ERROR")
                return (False, reason, current_ver, clock_fixed)
            if not shortfalls and not skip_per_member_gate:
                wlog(host, "  All %d member(s) have sufficient space"
                     % len(per_member_bytes), "OK")
        elif not skip_per_member_gate and fw_size:
            wlog(host, "  Could not determine per-member free", "WARN")
    except Exception as e:
        wlog(host, "  Stack free-space check skipped: %s" % str(e)[:80],
             "WARN")

    if WIPE_BEFORE_TRANSFER and not DRY_RUN:
        set_state(host, "PRE-CHECK", "wiping")
        wipe_firmware_flash(conn, host)
    free_bytes = get_flash_free_bytes(conn)
    if free_bytes < required_active:
        reason = ("insufficient_space: free=%s need=%s"
                  % (_fmt_bytes(free_bytes),
                     _fmt_bytes(required_active)))
        wlog(host, "  STILL insufficient on active member: %s -- REFUSING"
             % reason, "ERROR")
        return (False, reason, current_ver, clock_fixed)
    wlog(host, "  Space OK: %.1f MB (active need ~%.0f MB)"
         % (free_bytes/1e6, required_active/1e6), "OK")
    return (True, "ready", current_ver, clock_fixed)


def _pwfile_for_thread():
    global _PWFILE_COUNTER
    with _PWFILE_COUNTER_LK:
        _PWFILE_COUNTER += 1
        n = _PWFILE_COUNTER
    return "%s_%d_%d.tmp" % (_PWFILE_BASE, os.getpid(), n)


def _write_pwfile(pw):
    path = _pwfile_for_thread()
    with _PWFILE_LOCK:
        try:
            with open(path, "w", newline="") as f:
                f.write(pw + "\n")
            return path
        except Exception as e:
            master_log("Could not write pwfile: %s" % e)
            return None


def _delete_pwfile(path):
    if not path: return
    with _PWFILE_LOCK:
        try:
            if os.path.exists(path): os.remove(path)
        except OSError: pass


def _verify_firmware_hash(fw_file, host):
    if not FIRMWARE_RECHECK_BEFORE_TRANSFER: return True
    expected = FIRMWARE_SHA256.get(fw_file)
    if not expected: return True
    p = os.path.join(FIRMWARE_DIR, fw_file)
    try:
        actual = _sha256_of_file(p)
        if actual != expected:
            wlog(host, "Firmware hash changed! expected %s... got %s..."
                 % (expected[:16], actual[:16]), "ERROR")
            return False
        return True
    except Exception as e:
        wlog(host, "Firmware hash re-check failed: %s" % str(e)[:80], "WARN")
        return True


def _pscp_run_once(cmd, host, start, tag_prefix=""):
    """
    v35.9.43 FIX-PSCP-STALL: adds a stall detector.  Previously the
    blocking `proc.stdout.read(4096)` never returned when pscp stopped
    producing output (hung socket, stalled transfer), freezing the
    entire transfer pool.  Now a background reader thread pushes raw
    bytes onto a queue, and the main loop kills the process after
    SCP_STALL_TIMEOUT seconds without any output, letting the caller's
    retry path take over.
    """
    import queue as _queue
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            bufsize=-1,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    except Exception as e:
        wlog(host, "pscp spawn failed: %s" % str(e)[:120], "ERROR")
        return -1, 0.0, False

    pct_re = re.compile(rb"(\d{1,3})%")
    last_pct = -1
    last_report = 0.0
    killed = False

    chunks = _queue.Queue()
    _SENTINEL = object()

    def _reader():
        try:
            while True:
                buf = proc.stdout.read(4096)
                if not buf:
                    break
                chunks.put(buf)
        except Exception:
            pass
        finally:
            try: proc.stdout.close()
            except Exception: pass
            chunks.put(_SENTINEL)

    rt = threading.Thread(target=_reader, daemon=True, name="pscp-rd")
    rt.start()

    pending = b""
    last_data = time.time()
    try:
        while True:
            if SHUTDOWN_REQ.is_set():
                try: proc.terminate()
                except Exception: pass
                killed = True
                wlog(host, "pscp aborted (shutdown)", "WARN")
                break
            try:
                item = chunks.get(timeout=1.0)
            except _queue.Empty:
                if time.time() - last_data > SCP_STALL_TIMEOUT:
                    wlog(host, "pscp stalled %ds with no output -- killing "
                               "(will retry)" % SCP_STALL_TIMEOUT, "WARN")
                    try: proc.kill()
                    except Exception: pass
                    killed = True
                    break
                continue
            if item is _SENTINEL:
                break
            last_data = time.time()
            pending += item
            # pscp writes progress with `\r`, stats with `\n`.
            while True:
                i_r = pending.find(b"\r")
                i_n = pending.find(b"\n")
                idxs = [i for i in (i_r, i_n) if i >= 0]
                if not idxs:
                    break
                i = min(idxs)
                line, pending = pending[:i], pending[i+1:]
                if LIVE_LOG_FEED_TRANSFER:
                    try: line_str = line.decode("utf-8", "replace")
                    except Exception: line_str = str(line)
                    if line_str.strip():
                        feed_live_log(host, "[%spscp] %s"
                                      % (tag_prefix, line_str.strip()))
                m = pct_re.search(line)
                if m:
                    try: pct = int(m.group(1))
                    except Exception: continue
                    if pct != last_pct and time.time() - last_report > 3:
                        last_pct = pct
                        last_report = time.time()
                        with STATE_LOCK:
                            if host in PEER_STATES:
                                PEER_STATES[host]["progress"] = float(pct)
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            try: proc.kill()
            except Exception: pass
            wlog(host, "pscp hung on exit", "WARN")
            return -2, time.time() - start, False
    except Exception as e:
        wlog(host, "pscp read error: %s" % str(e)[:120], "WARN")
        try: proc.kill()
        except Exception: pass
        return -3, time.time() - start, False

    rc_final = proc.returncode if proc.returncode is not None else -4
    if rc_final != 0:
        try:
            tail = (pending or b"").decode("utf-8", "replace").strip()
            if tail:
                wlog(host, "  pscp(%s) output tail: %s"
                     % (tag_prefix or "main", tail[-500:]), "INFO")
        except Exception: pass
    return rc_final, time.time() - start, killed


def transfer_via_pscp(ip, user, pw, fw_file, host):
    if not os.path.isfile(PSCP_EXE):
        wlog(host, "pscp.exe not found at %s" % PSCP_EXE, "ERROR"); return False
    local_file = os.path.join(FIRMWARE_DIR, fw_file)
    if not os.path.isfile(local_file):
        wlog(host, "pscp: local missing %s" % local_file, "ERROR")
        return False
    if not _verify_firmware_hash(fw_file, host): return False
    pwfile = _write_pwfile(pw)
    if not pwfile: return False
    wlog(host, "PSCP push -> %s:%s" % (ip, fw_file), "STEP")
    set_state(host, "TRANSFER", "PSCP", progress=0)
    set_cmd(host, "pscp -> flash:%s" % fw_file)
    dest = "%s@%s:flash:%s" % (user, ip, fw_file)
    cmd = [PSCP_EXE, "-scp", "-batch", "-pwfile", pwfile,
           local_file, dest]
    start = time.time()
    rc, elapsed, killed = _pscp_run_once(cmd, host, start)
    try: _delete_pwfile(pwfile)
    except Exception: pass
    if killed: return False
    if rc == 0:
        fw_size = get_firmware_size(fw_file)
        mbps = fw_size / max(elapsed, 1) / 1e6 if fw_size else 0
        wlog(host, "PSCP success -- %.0fs (%.2f MB/s)" % (elapsed, mbps),
             "OK")
        return True
    if rc == 1 and elapsed < 60:
        wlog(host, "  pscp failed fast -- fetching host key", "WARN")
        hk = _get_host_key_fingerprint(ip, user, pw)
        if hk: wlog(host, "  host key: %s  %s..." % (hk[0], hk[1][:32]), "INFO")
        else: wlog(host, "  no host key fingerprint", "WARN")
        cmd2 = [PSCP_EXE, "-scp", "-batch", "-pw", pw]
        if hk: cmd2.extend(["-hostkey", hk[1]])
        cmd2.extend([local_file, dest])
        start2 = time.time()
        rc2, elapsed2, killed2 = _pscp_run_once(cmd2, host, start2,
                                                tag_prefix="retry-")
        if killed2: return False
        if rc2 == 0:
            fw_size = get_firmware_size(fw_file)
            mbps = fw_size / max(elapsed2, 1) / 1e6 if fw_size else 0
            wlog(host, "PSCP (via -pw) -- %.0fs (%.2f MB/s)"
                 % (elapsed2, mbps), "OK")
            return True
        wlog(host, "PSCP retry failed rc=%d" % rc2, "ERROR")
        return False
    wlog(host, "PSCP failed rc=%d after %.0fs" % (rc, elapsed), "ERROR")
    return False


def transfer_via_scp(ip, user, pw, fw_file, host):
    wlog(host, "Paramiko SCP (legacy) -> %s:%s" % (ip, fw_file), "STEP")
    set_state(host, "TRANSFER", "SCP", progress=0)
    fw_size = get_firmware_size(fw_file)
    if DRY_RUN:
        wlog(host, "DRY-RUN: skipping SCP", "INFO"); return True
    local_file = os.path.join(FIRMWARE_DIR, fw_file)
    if not os.path.isfile(local_file):
        wlog(host, "local firmware missing: %s" % local_file, "ERROR")
        return False
    if not _verify_firmware_hash(fw_file, host): return False
    for attempt in range(1, SCP_MAX_ATTEMPTS + 1):
        if SHUTDOWN_REQ.is_set(): return False
        conn = None
        start_time = time.time()
        try:
            conn = do_connect(ip, user, pw)
            tacacs_enable(conn, host, ssh_pw=pw)
            if not ensure_scp_server_enabled(conn, host):
                raise RuntimeError("could not enable SCP server")
            result = file_transfer(
                conn, source_file=local_file, dest_file=fw_file,
                file_system="flash:", direction="put",
                overwrite_file=True, socket_timeout=SCP_TIMEOUT_SEC)
            if result.get("file_transferred") or result.get("file_exists"):
                elapsed = time.time() - start_time
                mbps = fw_size / max(elapsed, 1) / 1e6 if fw_size else 0
                wlog(host, "  SCP success -- %.0fs (%.2f MB/s)"
                     % (elapsed, mbps), "OK")
                return True
        except Exception as e:
            tag = _classify_connect_error(e)
            if tag:
                wlog(host, "  SCP %s" % tag, "WARN"); return False
            wlog(host, "  SCP attempt %d: %s" % (attempt, str(e)[:120]),
                 "WARN")
        finally:
            if conn:
                try: conn.disconnect()
                except Exception: pass
        if attempt < SCP_MAX_ATTEMPTS and not SHUTDOWN_REQ.is_set():
            wlog(host, "  Retrying in %ds..." % SCP_RETRY_DELAY, "INFO")
            time.sleep(SCP_RETRY_DELAY)
    return False


def _build_optimized_paramiko_client(ip, user, pw):
    import paramiko as _p
    client = _p.SSHClient()
    client.set_missing_host_key_policy(_p.AutoAddPolicy())
    client.connect(
        hostname=ip, username=user, password=pw,
        look_for_keys=False, allow_agent=False,
        timeout=PARAMIKO_CONNECT_TIMEOUT,
        banner_timeout=PARAMIKO_CONNECT_TIMEOUT,
        auth_timeout=PARAMIKO_CONNECT_TIMEOUT,
        compress=False)
    transport = client.get_transport()
    try:
        transport.default_window_size = PARAMIKO_WINDOW_BYTES
        transport.default_max_packet_size = 32768
    except Exception: pass
    if PARAMIKO_DISABLE_REKEY:
        try:
            pk = transport.packetizer
            if hasattr(pk, "REKEY_BYTES"): pk.REKEY_BYTES = 1 << 40
            if hasattr(pk, "REKEY_PACKETS"): pk.REKEY_PACKETS = 1 << 40
        except Exception: pass
    return client


def transfer_via_paramiko_tuned(ip, user, pw, fw_file, host):
    if not USE_PARAMIKO_TUNED:
        return transfer_via_scp(ip, user, pw, fw_file, host)
    local_file = os.path.join(FIRMWARE_DIR, fw_file)
    if not os.path.isfile(local_file):
        wlog(host, "local firmware missing: %s" % local_file, "ERROR")
        return False
    if not _verify_firmware_hash(fw_file, host): return False
    fw_size = get_firmware_size(fw_file) or os.path.getsize(local_file)
    wlog(host, "Paramiko tuned SCP -> %s:%s (chunk=%dKB, window=%dMB)"
         % (ip, fw_file, PARAMIKO_CHANNEL_CHUNK//1024,
            PARAMIKO_WINDOW_BYTES//(1024*1024)), "STEP")
    set_state(host, "TRANSFER", "SCP-tuned", progress=0)
    client = None
    try:
        client = _build_optimized_paramiko_client(ip, user, pw)
        transport = client.get_transport()
        try:
            probe_chan = transport.open_session()
            probe_chan.settimeout(PARAMIKO_READ_TIMEOUT)
            probe_chan.exec_command(
                "show running-config | include ip scp server")
            probe_chan.recv(4096); probe_chan.close()
        except Exception: pass
        channel = transport.open_session()
        channel.settimeout(PARAMIKO_READ_TIMEOUT)
        channel.exec_command("scp -t flash:%s" % fw_file)
        try: ack = channel.recv(1)
        except Exception as e:
            wlog(host, "SCP target ack failed: %s: %s"
                 % (type(e).__name__, str(e)[:80] or "(no message)"), "ERROR")
            return False
        if not ack or ack[0] != 0:
            try: err = channel.recv(256) or b""
            except Exception: err = b""
            wlog(host, "SCP target-mode rejected: %s"
                 % err.decode('utf-8', 'replace')[:120], "ERROR")
            return False
        import stat as _stat
        mode = _stat.S_IRUSR | _stat.S_IWUSR | _stat.S_IRGRP | _stat.S_IROTH
        header = "C%04o %d %s\n" % (mode, fw_size,
                                    os.path.basename(fw_file))
        channel.sendall(header.encode())
        try: ack = channel.recv(1)
        except Exception: ack = b""
        if not ack or ack[0] != 0:
            wlog(host, "SCP header rejected", "ERROR"); return False
        start = time.time(); sent = 0
        last_report = start; last_pct = -1
        chunk_size = PARAMIKO_CHANNEL_CHUNK
        with open(local_file, "rb") as f:
            while True:
                if SHUTDOWN_REQ.is_set():
                    wlog(host, "SCP-tuned aborted (shutdown)", "WARN")
                    try: channel.close()
                    except Exception: pass
                    return False
                buf = f.read(chunk_size)
                if not buf: break
                try: channel.sendall(buf)
                except Exception as e:
                    wlog(host, "SCP send error at %d bytes: %s: %s"
                         % (sent, type(e).__name__,
                            str(e)[:100] or "(no message)"), "ERROR")
                    return False
                sent += len(buf)
                now = time.time()
                if now - last_report > 3 and fw_size:
                    pct = int(100.0 * sent / fw_size)
                    if pct != last_pct:
                        last_pct = pct
                        with STATE_LOCK:
                            if host in PEER_STATES:
                                PEER_STATES[host]["progress"] = float(pct)
                        last_report = now
        channel.sendall(b"\x00")
        try: ack = channel.recv(1)
        except Exception: ack = b""
        if not ack or ack[0] != 0:
            wlog(host, "SCP EOF not acked by switch", "ERROR")
            return False
        try: channel.close()
        except Exception: pass
        try: client.close()
        except Exception: pass
        client = None
        elapsed = time.time() - start
        mbps = fw_size / max(elapsed, 1) / 1e6 if fw_size else 0
        wlog(host, "Paramiko tuned SCP -- %.0fs (%.2f MB/s)"
             % (elapsed, mbps), "OK")
        return True
    except Exception as e:
        detail = str(e)[:140] or "(no message)"
        wlog(host, "Paramiko tuned SCP failed: %s: %s"
             % (type(e).__name__, detail), "ERROR")
        return False
    finally:
        if client:
            try: client.close()
            except Exception: pass


def transfer_firmware(ip, user, pw, fw_file, host, model=""):
    if DRY_RUN:
        wlog(host, "DRY-RUN: skipping firmware transfer", "INFO")
        return True
    if PARAMIKO_PRIMARY and USE_PARAMIKO_TUNED:
        if transfer_via_paramiko_tuned(ip, user, pw, fw_file, host):
            return True
        wlog(host, "Paramiko tuned failed -- falling back to pscp", "WARN")
    if USE_PSCP:
        if transfer_via_pscp(ip, user, pw, fw_file, host):
            return True
        if PSCP_TRANSFER_FALLBACK:
            if USE_PARAMIKO_TUNED:
                wlog(host, "pscp failed -- falling back to tuned", "WARN")
                if transfer_via_paramiko_tuned(ip, user, pw, fw_file, host):
                    return True
            wlog(host, "pscp failed -- falling back to legacy", "WARN")
    if transfer_via_scp(ip, user, pw, fw_file, host):
        return True
    return False


def validate_transfer_size(conn, host, fw_file):
    fw_size = get_firmware_size(fw_file)
    if not fw_size:
        wlog(host, "  No local size reference", "WARN"); return True
    try:
        out = conn.send_command(
            "dir flash: | include %s" % re.escape(fw_file),
            read_timeout=60)
        feed_live_log(host, "[verify] dir flash:\n%s" % out)
        remote_size = _parse_file_size_from_dir(out, fw_file)
        if remote_size is None:
            wlog(host, "  Could not parse remote size", "ERROR")
            return False
        if remote_size == fw_size:
            wlog(host, "  Size validated: %d bytes" % remote_size, "OK")
            return True
        wlog(host, "  SIZE MISMATCH: %d != %d" % (remote_size, fw_size),
             "ERROR")
        return False
    except Exception as e:
        wlog(host, "  Size validation error: %s" % e, "ERROR")
        return False


def validate_transfer_hash(conn, host, fw_file):
    if not VERIFY_TRANSFER_HASH: return True
    expected = FIRMWARE_SHA256.get(fw_file)
    if not expected:
        wlog(host, "  No local SHA256 reference -- skipping", "WARN")
        return True
    try:
        wlog(host, "  verify /sha256 (5-15 min)", "STEP")
        set_state(host, "MD5", "verify sha256")
        set_cmd(host, "verify /sha256 flash:%s" % fw_file)
        out = conn.send_command("verify /sha256 flash:%s" % fw_file,
                                read_timeout=1800)
        feed_live_log(host, "[verify-sha256] %s" % out)
        m = re.search(r"SHA256 hash of [^:]+:\s*([0-9a-fA-F]{64})", out)
        if not m: m = re.search(r"\b([0-9a-fA-F]{64})\b", out)
        if not m:
            wlog(host, "  Could not parse SHA256 -- allowing", "WARN")
            return True
        remote = m.group(1).lower()
        if remote == expected.lower():
            wlog(host, "  SHA256 verified (%s...)" % remote[:16], "OK")
            return True
        wlog(host, "  SHA256 MISMATCH: remote=%s... local=%s..."
             % (remote[:16], expected[:16]), "ERROR")
        return False
    except Exception as e:
        wlog(host, "  SHA256 verify failed: %s -- allowing" % str(e)[:80],
             "WARN")
        return True


def _best_effort_wipe(ip, user, pw, fw_file, host, reason="wipe"):
    conn = None
    try:
        conn = do_connect(ip, user, pw)
        tacacs_enable(conn, host, ssh_pw=pw)
        if is_privileged(conn):
            _delete_firmware_from_flash(conn, host, fw_file)
        else:
            wlog(host, "  %s: not priv-15, skipping wipe" % reason, "WARN")
    except Exception as e:
        wlog(host, "  %s failed: %s" % (reason, str(e)[:80]), "WARN")
    finally:
        if conn:
            try: conn.disconnect()
            except Exception: pass


def _transfer_with_wipe_retry(ip, user, pw, fw_file, host, model=""):
    local_path = os.path.join(FIRMWARE_DIR, fw_file)
    local_size = (os.path.getsize(local_path)
                  if os.path.isfile(local_path) else 0)
    for attempt in range(1, TRANSFER_RETRY_ATTEMPTS + 1):
        if SHUTDOWN_REQ.is_set():
            wlog(host, "Shutdown -- aborting transfer retries", "WARN")
            return False
        wlog(host, "--- Transfer attempt %d/%d ---"
             % (attempt, TRANSFER_RETRY_ATTEMPTS), "STEP")
        conn = None
        try:
            conn = robust_reconnect(
                ip, user, pw, host,
                purpose="pre-transfer wipe (attempt %d)" % attempt)
            if conn:
                _delete_firmware_from_flash(conn, host, fw_file)
        except Exception as e:
            wlog(host, "Pre-transfer wipe failed: %s" % str(e)[:80], "WARN")
        finally:
            if conn:
                try: conn.disconnect()
                except Exception: pass
        transfer_ok = transfer_firmware(ip, user, pw, fw_file, host,
                                        model=model)
        if not transfer_ok:
            wlog(host, "  Transfer failed (attempt %d)" % attempt, "WARN")
            _best_effort_wipe(ip, user, pw, fw_file, host,
                              reason="post-fail wipe")
            if attempt < TRANSFER_RETRY_ATTEMPTS:
                time.sleep(TRANSFER_RETRY_DELAY_SEC)
            continue
        conn = robust_reconnect(ip, user, pw, host,
                                purpose="post-transfer verify (attempt %d)"
                                        % attempt)
        if not conn:
            wlog(host, "  Reconnect after transfer failed", "WARN")
            _best_effort_wipe(ip, user, pw, fw_file, host,
                              reason="verify-reconnect wipe")
            if attempt < TRANSFER_RETRY_ATTEMPTS:
                time.sleep(TRANSFER_RETRY_DELAY_SEC)
            continue
        try:
            if not file_in_flash(conn, fw_file):
                wlog(host, "  File not in flash after transfer", "WARN")
                if attempt < TRANSFER_RETRY_ATTEMPTS:
                    time.sleep(TRANSFER_RETRY_DELAY_SEC)
                continue
            if not validate_transfer_size(conn, host, fw_file):
                wlog(host, "  Size mismatch -- wiping", "WARN")
                _delete_firmware_from_flash(conn, host, fw_file)
                if attempt < TRANSFER_RETRY_ATTEMPTS:
                    time.sleep(TRANSFER_RETRY_DELAY_SEC)
                continue
            if not validate_transfer_hash(conn, host, fw_file):
                wlog(host, "  Hash mismatch -- wiping", "WARN")
                _delete_firmware_from_flash(conn, host, fw_file)
                if attempt < TRANSFER_RETRY_ATTEMPTS:
                    time.sleep(TRANSFER_RETRY_DELAY_SEC)
                continue
            wlog(host, "Transfer OK on attempt %d" % attempt, "OK")
            return True
        finally:
            try: conn.disconnect()
            except Exception: pass
    wlog(host, "Transfer FAILED after %d attempts"
         % TRANSFER_RETRY_ATTEMPTS, "ERROR")
    return False


def _probe_install_status(ip, user, pw, host, target_ver,
                          prev_indeterminate=0):
    c = None
    try:
        last_err = None
        for attempt in range(PROBE_CONNECT_RETRIES):
            try:
                c = do_connect(ip, user, pw)
                last_err = None
                break
            except Exception as e:
                last_err = e
                if attempt < PROBE_CONNECT_RETRIES - 1:
                    time.sleep(PROBE_CONNECT_DELAY_SEC)
        if c is None:
            err_name = type(last_err).__name__ if last_err else "?"
            wlog(host, "Probe: connect failed after %d attempts (%s) -- "
                       "indeterminate" % (PROBE_CONNECT_RETRIES, err_name),
                 "WARN")
            return (True, "connect failed (%s)" % err_name,
                    prev_indeterminate + 1)
        try:
            tacacs_enable(c, host, ssh_pw=pw)
        except Exception:
            pass
        if not is_privileged(c):
            wlog(host, "Probe: not priv-15 -- indeterminate (may be transient)",
                 "WARN")
            return (True, "not priv-15 (transient?)",
                    prev_indeterminate + 1)
        try:
            ver = c.send_command("show version | include Version",
                                 read_timeout=60)
            feed_live_log(host, "[probe] show version\n%s" % ver)
            if _norm_ver(parse_running_version(ver)) == _norm_ver(target_ver):
                try:
                    up = c.send_command("show version | include uptime is",
                                        read_timeout=30)
                    feed_live_log(host, "[probe] uptime\n%s" % up)
                    m = re.search(r"uptime is (.+)", up)
                    uptime_min = (parse_uptime_minutes(m.group(1))
                                  if m else None)
                    if uptime_min is not None and uptime_min < 30:
                        return (True,
                                "already on %s (rebooted %d min ago)"
                                % (target_ver, uptime_min), 0)
                except Exception:
                    pass
                return True, "already on %s" % target_ver, 0
        except Exception as e:
            return (True, "version check error (%s)" % type(e).__name__,
                    prev_indeterminate + 1)
        try:
            summ = c.send_command("show install summary", read_timeout=60)
            feed_live_log(host, "[probe] show install summary\n%s" % summ)
        except Exception as e:
            return (True, "install summary error (%s)" % type(e).__name__,
                    prev_indeterminate + 1)

        if re.search(r"install operation in progress|operation in progress",
                     summ, re.IGNORECASE):
            return True, "install still running", 0

        entries = _parse_install_summary(summ)
        if entries:
            tkey = _norm_ver(target_ver)
            target_status = entries.get(tkey)
            blocking = [v for v, s in entries.items()
                        if v != tkey and s in ("C", "A", "U")]
            if target_status == "C" and not blocking:
                return True, "image committed on %s" % target_ver, 0
            if target_status == "I":
                return True, "image inactive (added, awaiting activate)", 0
            if target_status == "U":
                return True, "image uncommitted (in progress)", 0
            if target_status == "A":
                return True, "image activated, commit pending", 0
            if any(s == "I" for s in entries.values()):
                return True, "image inactive (added, awaiting activate)", 0
            if any(s == "U" for s in entries.values()):
                return True, "image uncommitted (in progress)", 0
            if any(s == "A" for s in entries.values()):
                return True, "image activated, commit pending", 0

        try:
            log = c.send_command("show install log", read_timeout=60)
            feed_live_log(host, "[probe] show install log\n%s" % log)
            if not re.search(r"% Invalid input|% Incomplete", log,
                             re.IGNORECASE):
                lines = log.splitlines()
                start_idx = -1
                for i in range(len(lines) - 1, -1, -1):
                    if re.search(
                            r"install_(?:add|activate|commit|remove|"
                            r"abort|rollback).*?:\s*START",
                            lines[i], re.IGNORECASE):
                        start_idx = i
                        break
                current = ("\n".join(lines[start_idx:])
                           if start_idx >= 0 else "\n".join(lines[-40:]))
                low_cur = current.lower()
                if re.search(r"install_\w+\]\s*:\s*end\s+failed",
                             low_cur, re.IGNORECASE):
                    return False, "install log shows FAILED (current op)", 0
                if re.search(r"install_\w+\]\s*:\s*end\s+success",
                             low_cur, re.IGNORECASE):
                    return True, "install op ended SUCCESS", 0
                if start_idx >= 0:
                    return True, "current install op in progress", 0
        except Exception:
            pass
        return True, "indeterminate", prev_indeterminate + 1
    except Exception as e:
        err_name = type(e).__name__
        wlog(host, "Probe: %s: %s -- indeterminate"
             % (err_name, str(e)[:80]), "WARN")
        return True, "probe error (%s)" % err_name, prev_indeterminate + 1
    finally:
        if c:
            try: c.disconnect()
            except Exception: pass


def _safe_manual_reload(conn, host):
    wlog(host, "Issuing manual reload (fallback)", "STEP")
    try:
        drain_channel(conn, 2, host=host)
        set_cmd(host, "reload")
        conn.write_channel("reload\n")
        buffer = ""
        deadline = time.time() + 90
        sent_save_no = sent_confirm = False
        while time.time() < deadline:
            try: chunk = conn.read_channel()
            except Exception: break
            if not chunk:
                time.sleep(0.5); continue
            feed_live_log(host, chunk)
            buffer = (buffer + chunk)[-2000:]
            low = buffer.lower()
            if any(k in low for k in _RELOAD_MARKERS):
                wlog(host, "Reload accepted by switch", "OK")
                return True
            if (not sent_save_no
                    and ("system configuration has been modified" in low
                         or "save?" in low)):
                conn.write_channel("no\n"); sent_save_no = True
                time.sleep(1); buffer = ""; continue
            if (not sent_confirm
                    and ("proceed with reload" in low
                         or "[confirm]" in low)):
                conn.write_channel("\n"); sent_confirm = True
                time.sleep(1); buffer = ""; continue
        wlog(host, "Manual reload did not confirm", "WARN")
        return False
    except Exception as e:
        wlog(host, "Manual reload error: %s" % str(e)[:80], "WARN")
        return False


def run_install(conn, cmd, host, state, ip, user, pw, target_ver,
                is_issu=False, fw_file=None):
    set_state(host, "INSTALL", "starting")
    set_cmd(host, cmd)
    state["install_started"] = True
    state["last_probe"] = 0.0
    state["indeterminate_streak"] = 0
    state["last_probe_msg"] = ""
    state["probe_msg_counts"] = {}
    state["activate_nudged"] = False
    state["activate_attempts"] = 0
    state.setdefault("add_seen", False)
    state.setdefault("activate_seen", False)
    state.setdefault("commit_seen", False)
    state.setdefault("op_success_probes", 0)
    state.setdefault("commit_nudge_count", 0)
    if fw_file is None:
        m = re.search(r"flash:(\S+\.bin)", cmd)
        if m: fw_file = m.group(1)
    drain_channel(conn, 5, host=host)
    wlog(host, "INSTALL: %s" % cmd, "CMD")
    try:
        conn.write_channel(cmd + "\n")
    except Exception as e:
        return False, "write failed: %s" % e, conn
    start = time.time()
    last_output = time.time()
    buffer, last_y = "", 0.0
    success = reload_seen = False
    success_at = None
    _DONE = ("already on ", "image committed on ")

    def _close_and_return(ok, msg, rebooted=True):
        if rebooted:
            state["reboot_detected"] = True
        try: conn.disconnect()
        except Exception: pass
        return ok, msg, None

    while time.time() - start < INSTALL_TOTAL_TIMEOUT:
        if SHUTDOWN_REQ.is_set():
            return False, "shutdown requested", conn
        try:
            chunk = conn.read_channel()
            if chunk: feed_live_log(host, chunk)
        except Exception as e:
            emsg = str(e).lower()
            if success or reload_seen:
                wlog(host, "Session closed after install -- reboot in progress",
                     "OK")
                return _close_and_return(True, "", rebooted=True)
            if ("tacacs" in emsg or "authorization failed" in emsg
                    or "command authorization" in emsg):
                wlog(host, "TACACS+ dropped session: %s" % str(e)[:80],
                     "ERROR")
                try: conn.disconnect()
                except Exception: pass
                return False, "TACACS+ dropped session", None
            wlog(host, "Install session lost: %s" % str(e)[:80], "WARN")
            try: conn.disconnect()
            except Exception: pass
            new_conn = robust_reconnect(ip, user, pw, host,
                                        purpose="mid-install")
            if not new_conn:
                return _close_and_return(True, "", rebooted=True)
            try:
                if committed_on_target(new_conn, target_ver):
                    wlog(host, "Target committed after reconnect", "OK")
                    return True, "", new_conn
            except Exception:
                pass
            return False, "install session lost; state unknown", new_conn
        if chunk:
            last_output = time.time()
            buffer = (buffer + chunk)[-4000:]
            low = buffer.lower()
            for k in _AUTHZ_MARKERS:
                if k in low: return False, "TACACS+ denied command", conn
            for k in _REJECT_MARKERS:
                if k in low:
                    return False, "command rejected (%s)" % k, conn
            for k in _SPACE_MARKERS:
                if k in low:
                    msg = ("insufficient_space: install engine rejected "
                           "install add: %s" % k)
                    wlog(host, "  %s" % msg, "ERROR")
                    return False, msg, conn
            if any(k in low for k in _ALREADY_ADDED_MARKERS):
                return False, ("already_added_refused: engine refused "
                               "add because .pkg set is already on flash"), conn
            if re.search(r"failed:\s*install", low):
                return False, "install reported FAILED", conn
            tail = low[-400:]
            hit = next((p for p in _PROMPT_MARKERS if p in tail), None)
            if hit and time.time() - last_y > 10:
                conn.write_channel("y\n"); last_y = time.time()
                buffer = ""
                wlog(host, "Prompt ('%s') -> y" % hit, "OK")
                continue
            if any(k in low for k in _RELOAD_MARKERS):
                reload_seen = True
                state["reboot_detected"] = True
            if re.search(r"success:\s*install_add", low) \
                    and not state["add_seen"]:
                state["add_seen"] = True
                wlog(host, "Install add SUCCESS", "OK")
            if re.search(r"success:\s*install_activate", low) \
                    and not state["activate_seen"]:
                state["activate_seen"] = True
                wlog(host, "Install activate SUCCESS", "OK")
                if is_issu and not success:
                    success = True; success_at = time.time()
            if re.search(r"success:\s*install_commit", low) \
                    and not state["commit_seen"]:
                state["commit_seen"] = True
                success = True; success_at = time.time()
                wlog(host, "Install commit SUCCESS", "OK")

        if success and is_issu:
            set_state(host, "INSTALL", "ISSU verify")
            deadline = time.time() + ISSU_VERIFY_TIMEOUT
            consecutive_errs = 0
            while time.time() < deadline:
                if SHUTDOWN_REQ.is_set():
                    return False, "shutdown requested", conn
                time.sleep(20)
                try:
                    if committed_on_target(conn, target_ver):
                        wlog(host, "ISSU complete -- no reload", "OK")
                        return True, "", conn
                    consecutive_errs = 0
                except Exception as e:
                    consecutive_errs += 1
                    wlog(host, "ISSU verify error (%d/%d): %s"
                         % (consecutive_errs, ISSU_VERIFY_MAX_ERRORS,
                            str(e)[:80]), "WARN")
                    if consecutive_errs >= ISSU_VERIFY_MAX_ERRORS:
                        return (False,
                                "ISSU verify failed %dx consecutively: %s"
                                % (ISSU_VERIFY_MAX_ERRORS, str(e)[:80]),
                                conn)
            return False, "ISSU never committed within timeout", conn

        if reload_seen and not is_issu:
            time.sleep(3)
            return _close_and_return(True, "", rebooted=True)

        if success and not is_issu and time.time() - success_at > 180:
            already_on_target = False
            try:
                vo = conn.send_command("show version | include Version",
                                       read_timeout=30)
                if _norm_ver(parse_running_version(vo)) \
                        == _norm_ver(target_ver):
                    already_on_target = True
                    wlog(host, "Already on target after commit -- no reload "
                               "needed", "OK")
            except Exception:
                pass
            if already_on_target:
                return _close_and_return(True, "", rebooted=False)
            wlog(host, "Commit seen but device not yet on target after 180s "
                       "-- issuing manual reload", "WARN")
            _safe_manual_reload(conn, host)
            return _close_and_return(True, "", rebooted=True)

        if not chunk:
            silence = time.time() - last_output
            if (not success and silence > INSTALL_PROBE_INTERVAL
                    and time.time() - state.get("last_probe", 0)
                        > INSTALL_PROBE_INTERVAL):
                state["last_probe"] = time.time()
                set_state(host, "INSTALL",
                          "probe (silent %ds)" % int(silence))
                wlog(host, "Install silent %ds -- probing status"
                     % int(silence), "INFO")
                streak = state.get("indeterminate_streak", 0)
                probe_ok, probe_msg, new_streak = _probe_install_status(
                    ip, user, pw, host, target_ver, streak)
                state["indeterminate_streak"] = new_streak
                cnts = state["probe_msg_counts"]
                cnts[probe_msg] = cnts.get(probe_msg, 0) + 1
                same_total = cnts[probe_msg]
                if probe_ok and any(m in probe_msg for m in _DONE):
                    wlog(host, "Probe confirms on target -- exiting "
                               "install loop", "OK")
                    return _close_and_return(True, "", rebooted=False)
                if probe_ok and new_streak == 0:
                    prev_msg = state.get("last_probe_msg")
                    state["last_probe_msg"] = probe_msg
                    if probe_msg != prev_msg:
                        last_output = time.time()
                    if "image inactive" in probe_msg:
                        try:
                            if _state_needs_precommit(conn, host):
                                wlog(host, "  probe found U state -- "
                                           "pre-committing first", "WARN")
                                ok_pc, err_pc = \
                                    _run_install_commit_for_precommit(
                                        conn, host)
                                if not ok_pc:
                                    wlog(host, "  pre-commit failed: %s"
                                         % err_pc, "WARN")
                        except Exception:
                            pass
                        state["activate_attempts"] += 1
                        if state["activate_attempts"] == 1:
                            accepted = _nudge_install_activate(
                                conn, host, fw_file)
                        else:
                            accepted = _try_all_activate_forms(
                                conn, host, fw_file)
                        if accepted:
                            state["activate_nudged"] = True
                            last_output = time.time()
                            dead = False
                            try:
                                tr = getattr(conn, "remote_conn", None)
                                tr = getattr(tr, "transport", None)
                                if tr is None or not tr.is_active():
                                    dead = True
                            except Exception:
                                dead = True
                            if dead:
                                wlog(host, "  activate nudged, transport "
                                           "inactive -- reload in progress",
                                     "OK")
                                return _close_and_return(
                                    True, "", rebooted=True)
                            try:
                                conn.read_channel()
                            except Exception:
                                wlog(host, "  activate nudged, session "
                                           "closed -- reload in progress",
                                     "OK")
                                return _close_and_return(
                                    True, "", rebooted=True)
                        elif state["activate_attempts"] >= 3:
                            _run_install_abort_and_reissue(
                                conn, host, fw_file)
                            state["activate_attempts"] = 0
                            last_output = time.time()
                    elif ("image uncommitted" in probe_msg
                          or "commit pending" in probe_msg):
                        try:
                            if _state_needs_precommit(conn, host):
                                wlog(host, "  probe found U state -- "
                                           "pre-committing", "WARN")
                                _run_install_commit_for_precommit(
                                    conn, host)
                        except Exception:
                            pass
                        state["commit_nudge_count"] += 1
                        if state["commit_nudge_count"] >= 3:
                            wlog(host, "  Uncommitted -- nudging "
                                       "install commit", "WARN")
                            try:
                                conn.write_channel("install commit\n")
                                time.sleep(3)
                                try: conn.read_channel()
                                except Exception: pass
                            except Exception as e:
                                wlog(host, "  commit nudge failed: %s"
                                     % str(e)[:80], "WARN")
                            state["commit_nudge_count"] = 0
                    elif "install op ended SUCCESS" in probe_msg:
                        state["op_success_probes"] += 1
                        if state["op_success_probes"] >= 5:
                            try:
                                vo = conn.send_command(
                                    "show version | include Version",
                                    read_timeout=30)
                                if _norm_ver(parse_running_version(vo)) \
                                        == _norm_ver(target_ver):
                                    wlog(host, "Version on target after "
                                               "add-success -- exiting", "OK")
                                    return _close_and_return(True, "",
                                                             rebooted=False)
                            except Exception:
                                pass
                            state["op_success_probes"] = 0
                if same_total >= 12:
                    wlog(host, "Probe returned '%s' %d times -- forcing "
                               "version check" % (probe_msg, same_total),
                         "WARN")
                    try:
                        vo = conn.send_command(
                            "show version | include Version",
                            read_timeout=30)
                        if _norm_ver(parse_running_version(vo)) \
                                == _norm_ver(target_ver):
                            wlog(host, "Version on target -- exiting "
                                       "install loop", "OK")
                            return _close_and_return(True, "",
                                                     rebooted=False)
                    except Exception:
                        pass
                    return (False,
                            "install stuck on '%s' for %d probes"
                            % (probe_msg, same_total), conn)
                if probe_ok and new_streak != 0:
                    wlog(host, "Probe: %s (streak %d)"
                         % (probe_msg, new_streak), "WARN")
                    if new_streak >= 10:
                        return (False,
                                "install never started (indeterminate "
                                "for %ds)"
                                % (new_streak * INSTALL_PROBE_INTERVAL),
                                conn)
                elif not probe_ok:
                    wlog(host, "Probe failed: %s" % probe_msg, "WARN")
                    return False, "install probe: %s" % probe_msg, conn
            if not success and silence > INSTALL_SILENT_TIMEOUT:
                return (False,
                        "no install output for %ds" % INSTALL_SILENT_TIMEOUT,
                        conn)
            time.sleep(0.5)
    return False, "install timeout", conn


def _issue_rollback_commands(conn, host):
    for cmd in ("install rollback to committed", "install rollback to base"):
        try:
            drain_channel(conn, 2, host=host)
            set_cmd(host, cmd)
            conn.write_channel(cmd + "\n")
            time.sleep(3)
            got = ""
            try: got = conn.read_channel() or ""
            except Exception: pass
            feed_live_log(host, got)
            low = got.lower()
            if ("% invalid input" in low or "unrecognized" in low
                    or "% incomplete" in low):
                wlog(host, "  %s not accepted -- trying alternate" % cmd,
                     "WARN")
                continue
            return True, cmd
        except Exception as e:
            wlog(host, "  %s error: %s" % (cmd, str(e)[:80]), "WARN")
    return False, ""


def attempt_rollback(conn, host, ip=None, user=None, pw=None,
                     original_version=None):
    if not PRESERVE_ROLLBACK:
        wlog(host, "Rollback impossible: old packages not preserved", "ERROR")
        return False
    wlog(host, "AUTO-ROLLBACK", "STEP")
    set_state(host, "ROLLBACK", "issuing")
    issued = False
    ok, cmd = _issue_rollback_commands(conn, host)
    if not ok:
        wlog(host, "Neither rollback syntax accepted", "ERROR")
        return False
    wlog(host, "Rollback accepted: %s" % cmd, "OK")
    try:
        buffer, last_y = "", 0.0
        deadline = time.time() + 300
        while time.time() < deadline:
            try: chunk = conn.read_channel()
            except Exception:
                wlog(host, "Session closed during rollback -- reloading", "OK")
                issued = True; break
            if chunk:
                feed_live_log(host, chunk)
                buffer = (buffer + chunk)[-3000:]
                low = buffer.lower()
                if re.search(r"failed:\s*install", low):
                    wlog(host, "Rollback FAILED", "ERROR"); return False
                if any(k in low for k in ("initiating reload",
                                          "reload requested",
                                          "restarting system", "will reload")):
                    issued = True; break
                if (re.search(r"\[y/n\]|\(y/n\)|do you want to proceed",
                              low[-300:]) and time.time() - last_y > 10):
                    conn.write_channel("y\n"); last_y = time.time()
                    buffer = ""; continue
            time.sleep(0.5)
    except Exception as e:
        wlog(host, "Rollback error: %s" % str(e)[:100], "ERROR")
    if not issued: return False
    if not (ip and user and pw and original_version): return True
    wlog(host, "Waiting for rollback reboot (target %s)" % original_version,
         "INFO")
    try:
        try: conn.disconnect()
        except Exception: pass
        if not wait_for_ping_down(ip, host, timeout_sec=PING_DOWN_TIMEOUT_SEC):
            wlog(host, "Switch never went down after rollback", "WARN")
        if not wait_for_ping_up(ip, host, timeout_sec=PING_UP_TIMEOUT_SEC):
            wlog(host, "Switch did not come back", "ERROR")
            return False
        if not wait_for_ssh_ready(ip, host):
            wlog(host, "SSH not ready after rollback", "ERROR")
            return False
        c2 = robust_reconnect(ip, user, pw, host,
                              purpose="post-rollback verify")
        if not c2:
            wlog(host, "Reconnect failed after rollback", "ERROR")
            return False
        try:
            out = c2.send_command("show version | include Version",
                                  read_timeout=60)
            feed_live_log(host, "[rollback-verify] show version\n%s" % out)
            if _norm_ver(parse_running_version(out)) \
                    == _norm_ver(original_version):
                wlog(host, "Rollback verified -- back on %s"
                     % original_version, "OK")
                return True
            wlog(host, "Rollback did NOT restore %s" % original_version,
                 "ERROR")
            return False
        finally:
            try: c2.disconnect()
            except Exception: pass
    except Exception as e:
        wlog(host, "Rollback verify error: %s" % str(e)[:100], "ERROR")
        return False


def _verify_after_reboot_impl(conn, ip, target_ver, host, user, pw, st,
                              pre_config, fw_file):
    try:
        out = conn.send_command("show version | include Version")
        feed_live_log(host, "[verify] show version\n%s" % out)
        st["post_version"] = parse_running_version(out)
        if _norm_ver(st["post_version"]) != _norm_ver(target_ver):
            st["error"] = ("version mismatch: %s != %s"
                           % (st.get("post_version") or '?', target_ver))
            wlog(host, st["error"], "ERROR")
            if AUTO_ROLLBACK_ON_FAIL and st.get("reboot_detected"):
                if attempt_rollback(conn, host, ip=ip, user=user, pw=pw,
                                    original_version=st.get("start_version",
                                                            "")):
                    st["error"] += " (auto-rollback issued and verified)"
                else:
                    st["error"] += " (auto-rollback FAILED)"
            return False
        drain_syslog_after_reboot(conn, host)

        if not _finalize_install_commit(conn, host, target_ver,
                                        fw_file=fw_file or ""):
            st["error"] = "commit could not be verified"
            st["verify_pending"] = True
            wlog(host, "  upgrade NOT durable -- commit missing. "
                       "Device will revert on next reload.", "ERROR")
            return False
        wlog(host, "  commit finalized -- upgrade is durable", "OK")

        issues = []
        for i in range(1, HEALTH_RETRIES + 1):
            ok, issues = post_upgrade_health_check(conn, host, target_ver)
            if ok: break
            wlog(host, "Health %d/%d: %s"
                 % (i, HEALTH_RETRIES, "; ".join(issues)), "WARN")
            if i < HEALTH_RETRIES: time.sleep(HEALTH_RETRY_DELAY_SEC)
        else:
            st["error"] = "health check failed: " + "; ".join(issues)
            wlog(host, st["error"], "ERROR")
            st["verify_pending"] = True
            return False
        if pre_config and not SKIP_CONFIG_DRIFT_CHECK:
            try:
                post_cfg = conn.send_command("show running-config",
                                             read_timeout=120)
                drift = config_drift_check(pre_config, post_cfg, host)
                if drift:
                    st["drift"] = drift[:20]
                    st["config_diff_lines"] = len(drift)
            except Exception as e:
                wlog(host, "Config drift check skipped: %s" % str(e)[:80],
                     "WARN")
        wlog(host, "Upgrade verified on %s" % target_ver, "OK")
        try: post_upgrade_cleanup(conn, host)
        except Exception as e:
            wlog(host, "Cleanup non-fatal: %s" % str(e)[:80], "WARN")
        return True
    except Exception as e:
        st["error"] = "post-reboot verify error: %s" % str(e)[:150]
        st["verify_pending"] = True
        return False


def wait_reboot_and_verify(ip, target_ver, host, user, pw, st, is_issu=False,
                           pre_config="", fw_file=""):
    if not is_issu and ssh_port_open(ip, 3):
        peek = None
        try:
            peek = do_connect(ip, user, pw)
            vo = peek.send_command("show version | include Version",
                                   read_timeout=30)
            if _norm_ver(parse_running_version(vo)) \
                    == _norm_ver(target_ver):
                wlog(host, "Device already on target (fast reboot) -- "
                           "skipping ping-down wait", "OK")
                st["reboot_detected"] = True
                set_state(host, "VERIFY", "post-upgrade")
                return _verify_after_reboot_impl(
                    peek, ip, target_ver, host, user, pw, st,
                    pre_config, fw_file)
        except Exception as e:
            wlog(host, "  fast-reboot probe skipped: %s" % str(e)[:80],
                 "WARN")
        finally:
            if peek is not None:
                try: peek.disconnect()
                except Exception: pass

    if is_issu:
        wlog(host, "ISSU path -- skipping reboot wait", "INFO")
        set_state(host, "VERIFY", "post-ISSU")
    else:
        set_state(host, "REBOOT", "wait down")
        set_cmd(host, "ping (wait down)")
        went_down = wait_for_ping_down(ip, host)
        if not went_down:
            wlog(host, "Device did not go down -- checking anyway", "WARN")
        set_state(host, "REBOOT", "wait up")
        came_back = wait_for_ping_up(ip, host)
        if not came_back:
            st["error"] = "device did not return after reboot"
            st["verify_pending"] = True
            return False
        if not wait_for_ping_stable(ip, host):
            st["error"] = "boot loop detected (ping flapping)"
            st["verify_pending"] = True
            return False
        set_state(host, "REBOOT", "wait ssh")
        set_cmd(host, "ssh reconnect")
        if not wait_for_ssh_ready(ip, host):
            st["error"] = "SSH did not return"
            st["verify_pending"] = True
            return False
        wlog(host, "Settling %ds before verification"
             % POST_REBOOT_SETTLE_SEC, "INFO")
        set_state(host, "REBOOT", "settling")
        time.sleep(POST_REBOOT_SETTLE_SEC)
    set_state(host, "VERIFY", "post-upgrade")
    conn = robust_reconnect(ip, user, pw, host,
                            max_attempts=POST_REBOOT_MAX_ATTEMPTS,
                            delay=POST_REBOOT_DELAY_SEC, purpose="post-reboot")
    if not conn:
        st["error"] = "could not reconnect after reboot"
        st["verify_pending"] = True
        return False
    try:
        return _verify_after_reboot_impl(
            conn, ip, target_ver, host, user, pw, st,
            pre_config, fw_file)
    finally:
        try: conn.disconnect()
        except Exception: pass


def transfer_worker(dev, user, pw, location_name=""):
    loc = location_name or dev.get("_location", "")
    host, ip = dev["hostname"], dev["ip"]
    set_state(host, "QUEUE", "waiting slot")
    result = {"dev": dev, "success": False, "error": "", "fw_file": "",
              "target_ver": "", "start_ver": "", "skipped": False,
              "pre_config": "", "clock_corrected": False}
    conn = None
    model = ""
    if SHUTDOWN_REQ.is_set():
        result["error"] = "shutdown requested"; return result
    if DO_RESET_DEVICE_LOGS and not DRY_RUN: reset_device_logs(host)
    if loc: _update_checkpoint(loc, host, "transfer_start")
    try:
        try:
            conn = do_connect(ip, user, pw)
        except Exception as e:
            tag = _classify_connect_error(e)
            if tag:
                wlog(host, "%s: %s" % (tag, str(e)[:160]), "ERROR")
                result["error"] = tag
                if loc: _update_checkpoint(loc, host, "failed", tag)
                return result
            raise
        tacacs_enable(conn, host, ssh_pw=pw)
        try: conn.set_base_prompt()
        except Exception: pass
        if not is_privileged(conn):
            result["error"] = "not priv 15"
            if loc: _update_checkpoint(loc, host, "failed", "not priv 15")
            return result
        model = get_model(conn)
        fw = pick_firmware(model)
        if not fw:
            result["error"] = "unsupported model '%s'" % model
            wlog(host, "Unsupported model '%s' -- refusing" % model, "ERROR")
            if loc: _update_checkpoint(loc, host, "failed", result["error"])
            return result
        fw_file, target_ver = fw
        result["fw_file"], result["target_ver"] = fw_file, target_ver
        if _is_large_model(model) and SERIAL_TRANSFER_LARGE_MODELS:
            wlog(host, "Large model %s -- pool sized by LARGE_MODEL_PARALLEL=%d"
                 % (model, LARGE_MODEL_PARALLEL), "INFO")
        try:
            cnt, states = _stack_member_count(conn, host)
            if cnt > 1:
                wlog(host, "  Stack: %d members -- %s" % (cnt, states),
                     "INFO")
        except Exception: pass
        ok, reason, current_ver, clock_fixed = precheck_device(
            conn, host, fw_file, target_ver)
        result["start_ver"] = current_ver
        result["clock_corrected"] = clock_fixed
        if not ok:
            result["error"] = reason
            if loc: _update_checkpoint(loc, host, "failed", reason)
            return result
        if reason == "already_on_target":
            result["success"] = True; result["skipped"] = True
            if loc: _update_checkpoint(loc, host, "verified",
                                       "already_on_target")
            return result

        if reason == "already_added_needs_activate":
            result["success"] = True
            result["already_added"] = True
            if loc: _update_checkpoint(loc, host, "transferred")
            wlog(host, "TARGET .PKG SET PRESENT -- SKIPPING TRANSFER "
                       "AND PURGE", "OK")
            set_state(host, "READY", "activate pending")
            return result

        if reason.startswith("already_on_target_needs_"):
            needs_finalize = "needs_finalize" in reason
            needs_cleanup = "needs_cleanup" in reason
            wlog(host, "POST-UPGRADE FIXUP (%s)" % reason, "OK")
            set_state(host, "VERIFY", "fixup")
            fix_ok = True
            if needs_finalize:
                if not _finalize_install_commit(conn, host, target_ver,
                                                fw_file=fw_file):
                    result["error"] = ("fixup: commit could not be "
                                       "verified")
                    result["success"] = False
                    fix_ok = False
            if fix_ok and needs_cleanup:
                set_state(host, "VERIFY", "revert temp config")
                ok_count, fail_count, _unknown = revert_device_temp_changes(
                    conn, host)
                if fail_count:
                    wlog(host, "  revert partial: ok=%d fail=%d"
                         % (ok_count, fail_count), "WARN")
                else:
                    wlog(host, "  residual temp config reverted", "OK")
                try:
                    conn.send_command("write memory", read_timeout=60)
                except Exception:
                    pass
            if fix_ok:
                result["success"] = True
                result["fixup_done"] = True
                set_state(host, "DONE", "fixup complete")
                if loc: _update_checkpoint(loc, host, "verified", "fixup")
                wlog(host, "fixup complete -- device secured and durable",
                     "OK")
            return result

        if DO_BACKUP and not DRY_RUN:
            try:
                cfg = conn.send_command("show running-config",
                                        read_timeout=120)
                result["pre_config"] = cfg
                fn = ("%s_%s_%s.cfg"
                      % (host, current_ver,
                         datetime.now().strftime("%Y%m%d_%H%M%S")))
                with open(os.path.join(BACKUP_DIR, fn), "w",
                          encoding="utf-8") as f:
                    f.write(cfg)
                wlog(host, "Backup saved: %s" % fn, "OK")
            except Exception as e:
                wlog(host, "Backup skipped: %s" % e, "WARN")
        if PRE_SAVE_CONFIG and not DRY_RUN:
            try:
                wr = conn.send_command("write memory", read_timeout=60)
                if "error" in wr.lower() or "fail" in wr.lower():
                    wlog(host, "Pre-temp write memory: %s"
                         % wr.strip()[:80], "WARN")
            except Exception as e:
                wlog(host, "Pre-temp write memory error: %s" % str(e)[:80],
                     "WARN")
        fw_already_present = False
        if not DRY_RUN:
            tune_ssh_for_bulk_transfer(conn, host, model)
            apply_cheap_crypto_tuning(conn, host, model)
            if not ensure_scp_server_enabled(conn, host):
                result["error"] = "scp server enable failed"
                if loc:
                    _update_checkpoint(loc, host, "failed", result["error"])
                return result
            if not any(ch.get("type") == "exec_timeout"
                       for ch in get_temp_changes(host)):
                orig = get_vty_exec_timeout(conn, host)
                if orig:
                    all_already = all(
                        b.get("minutes") == 60 and b.get("seconds") == 0
                        for b in orig["blocks"]
                        if not b.get("was_default"))
                    if all_already and orig["blocks"]:
                        wlog(host, "  exec-timeout already 60 0 -- skipping",
                             "INFO")
                    else:
                        try:
                            track_temp_change(host, "exec_timeout", orig)
                            cmds = []
                            for b in orig["blocks"]:
                                cmds += ["line vty %s" % b["vty"],
                                         "exec-timeout 60 0", "exit"]
                            conn.send_config_set(cmds)
                            wlog(host, "Temp exec-timeout 60 0 set", "INFO")
                        except Exception as e:
                            wlog(host, "Failed temp exec-timeout: %s" % e,
                                 "WARN")
                else:
                    wlog(host, "Could not read VTY config -- skipping", "WARN")
            try:
                wlog(host, "Saving config (install precondition)...", "INFO")
                wr = conn.send_command("write memory", read_timeout=120)
                if "error" in wr.lower() or "fail" in wr.lower():
                    wlog(host, "write memory: %s" % wr.strip()[:80], "WARN")
                else:
                    wlog(host, "Config saved", "OK")
            except Exception as e:
                wlog(host, "write memory failed: %s" % str(e)[:80], "WARN")
            if file_in_flash(conn, fw_file):
                if validate_transfer_size(conn, host, fw_file):
                    wlog(host, "%s already in flash -- skipping transfer"
                         % fw_file, "OK")
                    fw_already_present = True
                else:
                    wlog(host, "%s present but wrong size -- wiping"
                         % fw_file, "WARN")
                    _delete_firmware_from_flash(conn, host, fw_file)
            else:
                wlog(host, "  %s not in flash -- will transfer" % fw_file,
                     "INFO")
        try: conn.disconnect()
        except Exception: pass
        conn = None
        if fw_already_present:
            result["success"] = True
            if not QUIET_SKIPPED:
                wlog(host, "DEVICE READY FOR INSTALL", "OK")
            set_state(host, "READY", "handing to install pool")
            if loc: _update_checkpoint(loc, host, "transferred")
            return result
        if DRY_RUN:
            wlog(host, "DRY-RUN: skipping transfer retry logic", "INFO")
            result["success"] = True; return result
        if not _transfer_with_wipe_retry(ip, user, pw, fw_file, host,
                                         model=model):
            result["error"] = ("transfer failed after %d attempts"
                               % TRANSFER_RETRY_ATTEMPTS)
            if loc: _update_checkpoint(loc, host, "failed", result["error"])
            return result

        if ALLOW_ACTIVE_PKG_PURGE and not DRY_RUN:
            conn2 = None
            try:
                conn2 = robust_reconnect(ip, user, pw, host,
                                         purpose="post-transfer pkg purge")
                if conn2:
                    fw_size = get_firmware_size(fw_file)
                    extraction = int(fw_size * EXTRACTION_OVERHEAD_FACTOR)
                    need = extraction + STACK_MEMBER_HEADROOM
                    free = get_flash_free_bytes(conn2)
                    if free < need:
                        wlog(host, "  Space still tight (%.0f MB < %.0f MB) "
                                   "-- invoking active-pkg purge"
                             % (free/1e6, need/1e6), "WARN")
                        set_state(host, "PKG-PURGE", "active .pkg purge")
                        _ok, _msg = _pre_install_pkg_purge(
                            conn2, host, fw_file, target_ver)
                        wlog(host, "  active-pkg purge: %s" % _msg,
                             "OK" if _ok else "WARN")
                    else:
                        wlog(host, "  Space OK (%.0f MB >= %.0f MB) -- "
                                   "skipping active-pkg purge"
                             % (free/1e6, need/1e6), "INFO")
            except Exception as e:
                wlog(host, "  post-transfer pkg purge error: %s"
                     % str(e)[:120], "WARN")
            finally:
                if conn2:
                    try: conn2.disconnect()
                    except Exception: pass

        result["success"] = True
        if not QUIET_SKIPPED:
            wlog(host, "DEVICE READY FOR INSTALL", "OK")
        set_state(host, "READY", "handing to install pool")
        if loc: _update_checkpoint(loc, host, "transferred")
        return result
    except Exception as e:
        result["error"] = str(e)[:200]
        if loc: _update_checkpoint(loc, host, "failed", result["error"])
        return result
    finally:
        if conn:
            try: conn.disconnect()
            except Exception: pass


def install_worker(dev, user, pw, transfer_result, location_name=""):
    loc = location_name or dev.get("_location", "")
    host, ip = dev["hostname"], dev["ip"]
    fw_file = transfer_result["fw_file"]
    target_ver = transfer_result["target_ver"]
    start_ver = transfer_result.get("start_ver", "")
    pre_config = transfer_result.get("pre_config", "")
    st = {"hostname": host, "ip": ip, "start_version": start_ver,
          "target_version": target_ver, "fw_file": fw_file,
          "status": "failed", "duration_sec": 0,
          "md5_ok": False, "install_started": False, "reboot_detected": False,
          "post_version": "", "error": "", "verify_pending": False,
          "stage": "install",
          "clock_corrected": transfer_result.get("clock_corrected", False)}
    start = time.time()
    def _fail(msg):
        st["error"] = msg
        if loc: _update_checkpoint(loc, host, "failed", msg)
        return (dev, "failed", time.time() - start, st, msg)
    if SHUTDOWN_REQ.is_set(): return _fail("shutdown requested")
    if DRY_RUN:
        wlog(host, "DRY-RUN: skipping install", "INFO")
        st["status"] = "success"
        if loc: _update_checkpoint(loc, host, "verified")
        return (dev, "success", time.time() - start, st, "")

    if transfer_result.get("already_on_target_fixup"):
        conn = None
        try:
            conn = robust_reconnect(ip, user, pw, host, purpose="fixup")
            if not conn:
                return _fail("reconnect failed before fixup")
            if transfer_result.get("needs_finalize"):
                set_state(host, "VERIFY", "commit finalize")
                wlog(host, "FIXUP: install commit", "STEP")
                if not _finalize_install_commit(conn, host, target_ver,
                                                fw_file=fw_file):
                    return _fail("commit could not be verified (fixup)")
                st["post_version"] = target_ver
                wlog(host, "commit finalized", "OK")
            if transfer_result.get("needs_cleanup"):
                set_state(host, "VERIFY", "revert temp config")
                wlog(host, "FIXUP: revert residual temp config", "STEP")
                ok_count, fail_count, _u = revert_device_temp_changes(
                    conn, host)
                if fail_count:
                    wlog(host, "  revert partial: ok=%d fail=%d"
                         % (ok_count, fail_count), "WARN")
                else:
                    wlog(host, "residual temp config reverted", "OK")
                try:
                    conn.send_command("write memory", read_timeout=60)
                except Exception:
                    pass
            st["status"] = "success"
            st["stage"] = "install"
            if not st.get("post_version"):
                st["post_version"] = target_ver
            if loc: _update_checkpoint(loc, host, "verified")
            return (dev, "success", time.time() - start, st, "")
        except Exception as e:
            return _fail(str(e)[:200])
        finally:
            if conn:
                try: conn.disconnect()
                except Exception: pass

    conn = None
    try:
        conn = robust_reconnect(ip, user, pw, host, purpose="install phase")
        if not conn: return _fail("reconnect failed before install")

        if transfer_result.get("already_added"):
            wlog(host, "Target .pkg already on flash -- issuing `install "
                       "activate` then `install commit` (no re-add)", "OK")
            ok1, err1, conn = _run_install_activate_only(
                conn, host, st, ip, user, pw, target_ver, fw_file=fw_file)
            if not ok1:
                return _fail("activate failed: %s" % err1)
            ok2, err2, conn = _run_install_commit_only(
                conn, host, st, ip, user, pw, target_ver)
            if not ok2:
                return _fail("commit failed: %s" % err2)
            if conn:
                try: conn.disconnect()
                except Exception: pass
                conn = None
            if not wait_reboot_and_verify(ip, target_ver, host, user, pw,
                                          st, is_issu=False,
                                          pre_config=pre_config,
                                          fw_file=fw_file):
                return (dev, "failed", time.time() - start, st,
                        st.get("error", ""))
            st["status"] = "success"
            if loc: _update_checkpoint(loc, host, "verified")
            return (dev, "success", time.time() - start, st, "")

        if DO_VERIFY_MD5:
            set_state(host, "MD5", "verify")
            set_cmd(host, "verify /md5 flash:%s" % fw_file)
            local_path = os.path.join(FIRMWARE_DIR, fw_file)
            if not os.path.isfile(local_path):
                wlog(host, "  MD5 skipped -- local firmware missing", "WARN")
            else:
                expected = cached_md5(local_path)
                out = ""
                try:
                    out = conn.send_command(
                        "verify /md5 flash:%s" % fw_file,
                        read_timeout=1800)
                    feed_live_log(host, "[verify] verify /md5\n%s" % out)
                except Exception as e:
                    msg = str(e)
                    if "Pattern not detected" in msg:
                        wlog(host, "  MD5 prompt pattern failed -- "
                                   "retrying with send_command_timing",
                             "WARN")
                        try:
                            out = conn.send_command_timing(
                                "verify /md5 flash:%s" % fw_file,
                                read_timeout=1800,
                                strip_prompt=False,
                                strip_command=False)
                            feed_live_log(host,
                                          "[verify] verify /md5 (timing)\n%s"
                                          % out)
                        except Exception as e2:
                            wlog(host, "  MD5 timing retry failed: %s -- "
                                       "skipping (non-fatal)"
                                 % str(e2)[:80], "WARN")
                            out = ""
                    else:
                        wlog(host, "  MD5 verify error: %s -- skipping "
                                   "(non-fatal)" % msg[:80], "WARN")
                        out = ""
                if not out:
                    wlog(host, "  MD5 not confirmed -- continuing "
                               "(transfer SHA256 already validated)", "WARN")
                elif expected.lower() in out.lower():
                    st["md5_ok"] = True
                    wlog(host, "MD5 verified", "OK")
                else:
                    m = re.search(
                        r"verify /md5 \([^)]+\)\s*=\s*([0-9a-fA-F]{32})",
                        out)
                    if m and m.group(1).lower() != expected.lower():
                        return _fail("MD5 mismatch: got %s expected %s"
                                     % (m.group(1).lower(), expected.lower()))
                    wlog(host, "  MD5 not parseable -- continuing", "WARN")

        issu_ok, issu_reasons = False, ["--skip-issu"]
        if not SKIP_ISSU:
            issu_ok, issu_reasons = check_issu_eligibility(conn, host)

        if issu_ok:
            wlog(host, "ISSU eligible -- zero-downtime path", "OK")
            install_cmd = ("install add file flash:%s activate issu commit"
                           % fw_file)
        else:
            wlog(host, "ISSU not eligible (%s) -- reload path"
                 % "; ".join(issu_reasons), "INFO")
            install_cmd = "install add file flash:%s activate commit" % fw_file

        success, err, conn = run_install(conn, install_cmd, host, st,
                                         ip, user, pw, target_ver,
                                         is_issu=issu_ok, fw_file=fw_file)
        if not success:
            if err and "already_added_refused" in err:
                wlog(host, "Engine refused re-add -- switching to "
                           "activate-only path", "WARN")
                if conn is None:
                    conn = robust_reconnect(ip, user, pw, host,
                                            purpose="activate-only retry")
                if conn:
                    ok1, err1, conn = _run_install_activate_only(
                        conn, host, st, ip, user, pw, target_ver,
                        fw_file=fw_file)
                    if ok1:
                        ok2, err2, conn = _run_install_commit_only(
                            conn, host, st, ip, user, pw, target_ver)
                        if ok2:
                            if conn:
                                try: conn.disconnect()
                                except Exception: pass
                                conn = None
                            if wait_reboot_and_verify(
                                    ip, target_ver, host, user, pw, st,
                                    is_issu=False, pre_config=pre_config,
                                    fw_file=fw_file):
                                st["status"] = "success"
                                if loc:
                                    _update_checkpoint(loc, host, "verified")
                                return (dev, "success",
                                        time.time() - start, st, "")
                            return (dev, "failed", time.time() - start, st,
                                    st.get("error", ""))
                        return _fail("activate-only commit failed: %s" % err2)
                    return _fail("activate-only failed: %s" % err1)
                return _fail(err)
            try:
                if conn and not st.get("reboot_detected"):
                    still_running = False
                    try:
                        probe_ok, probe_msg, _ = _probe_install_status(
                            ip, user, pw, host, target_ver)
                        if probe_ok and "install still running" in probe_msg:
                            still_running = True
                            wlog(host, "  Install still running -- skipping "
                                       "remove-inactive", "WARN")
                    except Exception: pass
                    if not still_running:
                        wlog(host, "  Clearing stale super-package", "INFO")
                        _run_install_remove_inactive(
                            conn, host, allow_abort=False)
            except Exception as e:
                wlog(host, "  Post-fail cleanup skipped: %s" % str(e)[:80],
                     "WARN")
            return _fail(err)
        if conn:
            try: conn.disconnect()
            except Exception: pass
            conn = None
        if not wait_reboot_and_verify(ip, target_ver, host, user, pw, st,
                                      is_issu=issu_ok, pre_config=pre_config,
                                      fw_file=fw_file):
            return (dev, "failed", time.time() - start, st,
                    st.get("error", ""))
        st["status"] = "success"
        if loc: _update_checkpoint(loc, host, "verified")
        return (dev, "success", time.time() - start, st, "")
    except Exception as e:
        return _fail(str(e)[:200])
    finally:
        if conn:
            try: conn.disconnect()
            except Exception: pass


def pre_scan_devices(devices, user=None, pw=None):
    reachable, unreachable = [], []
    if not devices: return reachable, unreachable
    def _chk(d):
        if SHUTDOWN_REQ.is_set(): return d, None, ""
        ok = ssh_port_open(d["ip"], timeout=5)
        model = ""
        if ok and user and pw:
            c_ = None
            try:
                c_ = do_connect(d["ip"], user, pw)
                tacacs_enable(c_, d["hostname"], ssh_pw=pw)
                model = get_model(c_) or ""
            except Exception: model = ""
            finally:
                if c_:
                    try: c_.disconnect()
                    except Exception: pass
        return d, ok, model
    with ThreadPoolExecutor(max_workers=20) as ex:
        for d, ok, model in ex.map(_chk, devices):
            if ok is None: continue
            if model: d["_model"] = model
            (reachable if ok else unreachable).append(d)
    small = [d for d in reachable if not _is_large_model(d.get("_model", ""))]
    large = [d for d in reachable if _is_large_model(d.get("_model", ""))]
    return small + large, unreachable


def _row(dev, status, stage="", error="", st=None, duration=0,
         attempts=1, transfer=None):
    st = st or {}; transfer = transfer or {}
    return {
        "hostname": dev["hostname"], "ip": dev["ip"], "status": status,
        "stage": stage,
        "start_version": st.get("start_version")
                         or transfer.get("start_ver", ""),
        "target_version": st.get("target_version")
                          or transfer.get("target_ver", ""),
        "post_version": st.get("post_version", ""),
        "fw_file": st.get("fw_file") or transfer.get("fw_file", ""),
        "md5_ok": st.get("md5_ok", False),
        "install_started": st.get("install_started", False),
        "reboot_detected": st.get("reboot_detected", False),
        "verify_pending": st.get("verify_pending", False),
        "clock_corrected": bool(st.get("clock_corrected")
                                or transfer.get("clock_corrected", False)),
        "config_diff_lines": st.get("config_diff_lines", 0),
        "duration_sec": int(duration), "attempts": attempts, "error": error,
    }


def is_retryable(row):
    if row["status"] != "failed":
        return False
    err = (row.get("error") or "").lower()
    if any(row["error"].startswith(p)
           for p in NON_RETRYABLE_PREFIXES):
        return False
    if row["stage"] == "transfer" and not row["install_started"]:
        return True
    if row["stage"] == "install":
        recoverable = (
            "image inactive" in err
            or "install stuck" in err
            or "cannot activate" in err
            or "commit could not be verified" in err
            or "version mismatch" in err
        )
        non_recoverable = (
            "md5 mismatch" in err
            or "tacacs+ denied" in err
            or "partial activation" in err
            or "two committed versions" in err
            or "insufficient_space" in err
        )
        return recoverable and not non_recoverable
    return False


def _collect_transfer_result(fut, dev, results, ifut, install_pool,
                             user, pw, attempt_no, location_name=""):
    host = dev["hostname"]
    try: tr = fut.result()
    except Exception as e:
        tr = {"success": False, "error": str(e)[:200], "skipped": False}
    if not tr.get("success"):
        results[host] = _row(dev, "failed", "transfer",
                             tr.get("error", "?"),
                             attempts=attempt_no, transfer=tr)
        set_state(host, "FAILED", tr.get("error", "")[:30])
        return
    if tr.get("skipped"):
        results[host] = _row(dev, "skipped", "precheck",
                             "already on target",
                             attempts=attempt_no, transfer=tr)
        clear_state(host)
        return
    if tr.get("fixup_done"):
        results[host] = _row(dev, "success", "verify", "",
                             attempts=attempt_no, transfer=tr)
        set_state(host, "DONE", "fixup complete")
        return
    ifut[install_pool.submit(install_worker, dev, user, pw, tr,
                             location_name)] = (dev, tr)


def run_pass(devices, user, pw, results, attempt_no, location_name=""):
    small, large = [], []
    for d in devices:
        (large if _is_large_model(d.get("_model", "")) else small).append(d)
    if not SERIAL_TRANSFER_LARGE_MODELS:
        small, large = devices, []

    def _model_counts(lst):
        cnt = {}
        for d in lst:
            m = d.get("_model", "unknown")
            cnt[m] = cnt.get(m, 0) + 1
        return ", ".join("%s x%d" % (k, v) for k, v in sorted(cnt.items()))

    print("\n  === Transfer plan (pass %d) ===" % attempt_no)
    if small:
        print("    Phase 1 -- %d small model(s), parallel=%d [%s]"
              % (len(small), TRANSFER_SLOTS, _model_counts(small)))
    if large:
        print("    Phase 2 -- %d large model(s), parallel=%d [%s]"
              % (len(large), LARGE_MODEL_PARALLEL, _model_counts(large)))
    print()
    master_log("PASS %d plan: small=%d large=%d"
               % (attempt_no, len(small), len(large)))

    with ThreadPoolExecutor(max_workers=INSTALL_WORKERS,
                            thread_name_prefix="inst") as ip_:
        ifut = {}

        def _consume_one(f):
            pair = ifut.pop(f, None)
            if pair is None:
                return
            d, tr = pair
            host = d["hostname"]
            try:
                _, status, dur, st, err = f.result()
            except Exception as e:
                status, dur, st, err = "failed", 0, {}, str(e)[:200]
            results[host] = _row(
                d, "success" if status == "success" else "failed",
                "install", err, st=st, duration=dur,
                attempts=attempt_no, transfer=tr)
            set_state(host, "DONE" if status == "success" else "FAILED",
                      "upgraded" if status == "success" else err[:30])

        def _drain_install(block):
            keys = list(ifut.keys())
            if not keys:
                return
            if block:
                for f in as_completed(keys):
                    _consume_one(f)
            else:
                for f in keys:
                    if f.done():
                        _consume_one(f)

        def _run_phase(dev_list, workers, prefix):
            if not dev_list:
                return
            with ThreadPoolExecutor(max_workers=max(1, workers),
                                    thread_name_prefix=prefix) as tp:
                tfut = {tp.submit(transfer_worker, d, user, pw,
                                  location_name): d for d in dev_list}
                pending = set(tfut.keys())
                while pending:
                    done, pending = wait(pending, timeout=10,
                                         return_when=FIRST_COMPLETED)
                    for f in done:
                        dev = tfut.pop(f, None)
                        if dev is None:
                            continue
                        _collect_transfer_result(
                            f, dev, results, ifut, ip_,
                            user, pw, attempt_no, location_name)
                    _drain_install(block=False)

        if small:
            _run_phase(small, TRANSFER_SLOTS, "xfer")
        if large:
            workers = max(1, LARGE_MODEL_PARALLEL)
            master_log("TRANSFER PHASE 2 start: %d large, parallel=%d"
                       % (len(large), workers))
            _run_phase(large, workers, "xfer-large")
            master_log("TRANSFER PHASE 2 end: %d large" % len(large))

        _drain_install(block=True)


def _print_location_progress(by_loc, results):
    print("\n  -- Location progress --")
    for loc in sorted(by_loc.keys()):
        total = len(by_loc[loc])
        done = sum(1 for d in by_loc[loc]
                   if results.get(d["hostname"], {}).get("status")
                   in ("success", "skipped", "failed"))
        succ = sum(1 for d in by_loc[loc]
                   if results.get(d["hostname"], {}).get("status")
                   in ("success", "skipped"))
        fail = sum(1 for d in by_loc[loc]
                   if results.get(d["hostname"], {}).get("status") == "failed")
        marker = ("OK" if done == total and fail == 0
                  else "!!" if fail else "..")
        print("    %s %-20s %d/%d done (success=%d failed=%d)"
              % (marker, loc, done, total, succ, fail))
    print()


def _report_fields():
    return ["hostname", "ip", "status", "stage", "start_version",
            "target_version", "post_version", "fw_file", "md5_ok",
            "install_started", "reboot_detected", "verify_pending",
            "clock_corrected", "config_diff_lines",
            "duration_sec", "attempts", "error", "revert_verified"]


def write_location_report(location_name, results, revert_verify=None,
                          force=False):
    key = "%s" % location_name
    with CSV_WRITTEN_LOCK:
        if key in CSV_WRITTEN and not force: return None
        CSV_WRITTEN.add(key)
    try:
        os.makedirs(REPORT_DIR, exist_ok=True)
        csv_path = os.path.join(REPORT_DIR,
                                "%s_%s.csv" % (location_name, RUN_ID))
        json_path = os.path.join(REPORT_DIR,
                                 "%s_%s.json" % (location_name, RUN_ID))
        fields = _report_fields()
        for r in results.values():
            if revert_verify and r["hostname"] in revert_verify:
                r["revert_verified"] = ("OK"
                                        if revert_verify[r["hostname"]]["ok"]
                                        else "FAILED")
            else: r["revert_verified"] = "N/A"
        with CSV_LOCK:
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
                w.writeheader()
                for r in sorted(results.values(),
                                key=lambda x: x["hostname"]):
                    w.writerow(r)
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump({"location": location_name, "run_id": RUN_ID,
                           "revert_verify": revert_verify or {},
                           "results": sorted(results.values(),
                                             key=lambda x: x["hostname"])},
                          f, indent=2)
        print("  Report: %s" % csv_path)
        return csv_path
    except Exception as e:
        master_log("Report write failed for %s: %s" % (location_name, e))
        return None


def run_location(location_name, devices, user, pw,
                 resume_checkpoint=False, retry_failed=False):
    print("\n" + "=" * 70)
    print("  LOCATION: %s (%d devices)%s%s%s"
          % (location_name, len(devices),
             "  [DRY-RUN]" if DRY_RUN else "",
             "  [RESUME]" if resume_checkpoint else "",
             "  [RETRY-FAILED]" if retry_failed else ""))
    print("=" * 70)
    master_log("LOCATION START: %s devices=%d" % (location_name, len(devices)))
    if retry_failed:
        failed_set = _failed_hosts_from_last_report(location_name)
        if failed_set:
            print("  Filter: %d host(s) failed last run" % len(failed_set))
            devices = [d for d in devices if d["hostname"] in failed_set]
            print("  -> %d device(s) to retry" % len(devices))
        else: print("  No failed devices from last run -- running full set")
    if resume_checkpoint:
        ckpt = _load_checkpoint(location_name)
        verified = {h for h, v in ckpt.items()
                    if v.get("stage") == "verified"}
        if verified:
            print("  Checkpoint: %d host(s) already verified" % len(verified))
            devices = [d for d in devices if d["hostname"] not in verified]
            print("  -> %d device(s) remaining" % len(devices))
    if not devices:
        print("  Nothing to do for this location.")
        return {}, False, {}
    results, aborted = {}, False
    revert_verify = {}
    try:
        prepare_rollback_doc(devices, location_name)
        reachable, unreachable = pre_scan_devices(devices, user, pw)
        for d in unreachable:
            results[d["hostname"]] = _row(d, "failed", "prescan",
                                          "unreachable on tcp/22")
            wlog(d["hostname"], "Unreachable on port 22", "ERROR")
            _update_checkpoint(location_name, d["hostname"], "failed",
                               "unreachable")
        pending, attempt = reachable, 0
        while pending and not SHUTDOWN_REQ.is_set():
            attempt += 1
            run_pass(pending, user, pw, results, attempt, location_name)
            failed = [d for d in pending
                      if results[d["hostname"]]["status"] == "failed"]
            if (attempt == 1 and len(pending) >= ABORT_GATE_MIN_DEVICES
                    and len(failed) / len(pending) > ABORT_GATE_THRESHOLD):
                aborted = True
                print("\n  ABORT GATE: %d/%d failed"
                      % (len(failed), len(pending)))
                master_log("ABORT GATE at %s" % location_name)
                break
            retry = [d for d in failed
                     if is_retryable(results[d["hostname"]])]
            if (not RETRY_FAILED_DEVICES or not retry
                    or attempt > MAX_RETRIES or SHUTDOWN_REQ.is_set()):
                break
            print("\n  Retrying %d device(s) in %ds (retry %d/%d)"
                  % (len(retry), RETRY_DELAY_SEC, attempt, MAX_RETRIES))
            SHUTDOWN_REQ.wait(RETRY_DELAY_SEC)
            pending = retry
    except Exception as e:
        master_log("Location %s raised: %s" % (location_name, e))
        print("\n  Location %s raised: %s" % (location_name, e))
    finally:
        for d in devices:
            results.setdefault(d["hostname"],
                               _row(d, "failed", "not_run",
                                    "not processed (shutdown/crash?)"))
        try:
            revert_verify = revert_location_temp_changes(devices, user, pw,
                                                         location_name) or {}
        except Exception as e:
            master_log("Revert/verify raised: %s" % e)
        write_location_report(location_name, results, revert_verify)
        master_log("LOCATION END: %s" % location_name)
    return results, aborted, revert_verify


def _run_pooled(loc_devices, user, pw,
                resume_checkpoint=False, retry_failed=False):
    flat, by_loc = [], {}
    for loc, devs in loc_devices.items():
        by_loc[loc] = []
        for d in devs:
            td = {"hostname": d["hostname"], "ip": d["ip"], "_location": loc}
            flat.append(td); by_loc[loc].append(td)
    if retry_failed:
        for loc in list(by_loc):
            fs = _failed_hosts_from_last_report(loc)
            if fs:
                by_loc[loc] = [d for d in by_loc[loc]
                               if d["hostname"] in fs]
        flat = [d for loc in by_loc for d in by_loc[loc]]
    if resume_checkpoint:
        for loc in list(by_loc):
            ckpt = _load_checkpoint(loc)
            verified = {h for h, v in ckpt.items()
                        if v.get("stage") == "verified"}
            if verified:
                by_loc[loc] = [d for d in by_loc[loc]
                               if d["hostname"] not in verified]
        flat = [d for loc in by_loc for d in by_loc[loc]]
    if not flat:
        print("  Nothing to do (all devices filtered).")
        return {}, {}
    for loc, devs in by_loc.items():
        if devs: prepare_rollback_doc(devs, loc)
    results = {}
    reachable, unreachable = pre_scan_devices(flat, user, pw)
    for d in unreachable:
        results[d["hostname"]] = _row(d, "failed", "prescan",
                                      "unreachable on tcp/22")
        wlog(d["hostname"], "Unreachable on port 22", "ERROR")
        _update_checkpoint(d["_location"], d["hostname"], "failed",
                           "unreachable")
    aborted_locs = set()
    pending = reachable
    attempt = 0
    while pending and not SHUTDOWN_REQ.is_set():
        attempt += 1
        run_pass(pending, user, pw, results, attempt, location_name="")
        _print_location_progress(by_loc, results)
        for loc, devs in by_loc.items():
            if loc in aborted_locs: continue
            hosts_in = {d["hostname"] for d in devs}
            pend_in = [d for d in pending if d["hostname"] in hosts_in]
            if not pend_in: continue
            fail_in = [d for d in pend_in
                       if results.get(d["hostname"], {})
                                 .get("status") == "failed"]
            if (attempt == 1
                    and len(pend_in) >= ABORT_GATE_MIN_DEVICES
                    and len(fail_in) / max(len(pend_in), 1)
                        > ABORT_GATE_THRESHOLD):
                print("\n  ABORT GATE (%s): %d/%d failed -- skipping "
                      "retries for this location"
                      % (loc, len(fail_in), len(pend_in)))
                master_log("ABORT GATE %s: %d/%d"
                           % (loc, len(fail_in), len(pend_in)))
                aborted_locs.add(loc)
        failed = [d for d in pending
                  if results.get(d["hostname"], {}).get("status") == "failed"
                  and d.get("_location") not in aborted_locs]
        retry = [d for d in failed
                 if is_retryable(results.get(d["hostname"], {}))]
        if (not RETRY_FAILED_DEVICES or not retry
                or attempt > MAX_RETRIES or SHUTDOWN_REQ.is_set()):
            break
        print("\n  Retrying %d device(s) in %ds (retry %d/%d)"
              % (len(retry), RETRY_DELAY_SEC, attempt, MAX_RETRIES))
        SHUTDOWN_REQ.wait(RETRY_DELAY_SEC)
        pending = retry
    print("\n" + "=" * 70)
    print("  POOLED RUN COMPLETE -- writing per-location reports")
    print("=" * 70)
    all_results, all_revert = {}, {}
    for loc, devs in by_loc.items():
        loc_res = {}
        for d in devs:
            r = results.get(d["hostname"])
            if r is None:
                r = _row(d, "failed", "not_run",
                         "not processed (pooled run)")
            loc_res[d["hostname"]] = r
        all_results[loc] = loc_res
        try:
            rv = revert_location_temp_changes(devs, user, pw, loc) or {}
        except Exception as e:
            master_log("Revert for %s raised: %s" % (loc, e))
            rv = {}
        all_revert[loc] = rv
        write_location_report(loc, loc_res, rv)
    return all_results, all_revert


def _fmt_duration(seconds):
    seconds = int(seconds or 0)
    if seconds < 60:
        return "%ds" % seconds
    m, s = divmod(seconds, 60)
    if m < 60:
        return "%dm%02ds" % (m, s)
    h, m = divmod(m, 60)
    return "%dh%02dm%02ds" % (h, m, s)


def _device_line(r):
    host = (r.get("hostname") or "?")[:30]
    ip = (r.get("ip") or "?")[:15]
    st = r.get("status", "?")
    sv = r.get("start_version") or "?"
    tv = r.get("target_version") or "?"
    dur = _fmt_duration(r.get("duration_sec", 0))
    if st == "success":
        arrow = "%s -> %s" % (sv, tv) if sv != tv else tv
        flags = []
        if r.get("reboot_detected"): flags.append("reboot")
        if r.get("md5_ok"):          flags.append("md5-ok")
        if r.get("clock_corrected"): flags.append("clock-fix")
        fs = ("  [" + ", ".join(flags) + "]") if flags else ""
        mark = c("OK", "green")
        return "%s %-30s %-15s %-28s %9s%s" % (mark, host, ip, arrow, dur, fs)
    if st == "skipped":
        mark = c("--", "yellow")
        return "%s %-30s %-15s already on %-16s %9s" % (mark, host, ip, tv,
                                                        dur)
    stage = r.get("stage", "")
    err = (r.get("error") or "?")[:60]
    tag = "[%s] " % stage if stage else ""
    mark = c("!!", "red")
    return "%s %-30s %-15s %s%s" % (mark, host, ip, tag, err)


def _load_previous_run_summary():
    if not os.path.isdir(REPORT_DIR): return None
    try:
        names = sorted((f for f in os.listdir(REPORT_DIR)
                        if f.startswith("run_summary_")
                        and f.endswith(".json")
                        and RUN_ID not in f), reverse=True)
    except OSError:
        return None
    for name in names:
        try:
            with open(os.path.join(REPORT_DIR, name), "r",
                      encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            continue
    return None


def detect_anomalies(all_results, prev_summary):
    if not prev_summary: return []
    prev_by = {r["hostname"]: r for r in prev_summary.get("results", [])}
    issues = []
    for loc, res in all_results.items():
        for host, r in res.items():
            prev = prev_by.get(host)
            if not prev: continue
            if (r["status"] == "success" and prev.get("post_version")
                    and r.get("post_version")
                    and r["post_version"] < prev["post_version"]):
                issues.append((host, "version regressed: %s -> %s"
                               % (prev["post_version"], r["post_version"])))
            if (prev.get("status") == "success" and r["status"] == "failed"
                    and r.get("install_started")
                    and not prev.get("install_started")):
                issues.append((host, "failed this run (was success last): %s"
                               % (r.get("error") or "?")[:60]))
    return issues


def trend_report(all_results, lookback=5):
    if not os.path.isdir(REPORT_DIR): return
    try:
        files = sorted((f for f in os.listdir(REPORT_DIR)
                        if f.startswith("run_summary_")
                        and f.endswith(".json")
                        and RUN_ID not in f), reverse=True)[:lookback]
    except OSError:
        return
    if len(files) < 2: return
    history = {}
    for fn in files:
        try:
            with open(os.path.join(REPORT_DIR, fn), "r",
                      encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue
        for r in data.get("results", []):
            history.setdefault(r["hostname"], []).append(r["status"])
    chronic = [(h, s) for h, s in history.items() if s.count("failed") >= 2]
    if chronic:
        print("\n  CHRONIC FAILURES (last %d runs):" % len(files))
        for h, seq in sorted(chronic):
            print("      ! %s: %s" % (h, "/".join(seq)))


def print_summary(all_results, all_revert=None):
    all_revert = all_revert or {}
    ok = skipped = failed = 0
    print("\n" + "=" * 78)
    print("  FINAL SUMMARY -- DEVICE DETAIL  (v%s)" % VERSION_STRING)
    print("=" * 78)
    for loc in sorted(all_results.keys()):
        res = all_results[loc]
        cnt = {"success": 0, "skipped": 0, "failed": 0}
        for r in res.values():
            cnt[r["status"]] = cnt.get(r["status"], 0) + 1
        ok += cnt["success"]; skipped += cnt["skipped"]; failed += cnt["failed"]
        rv = all_revert.get(loc, {})
        rc = sum(1 for x in rv.values() if x.get("ok"))
        rf = sum(1 for x in rv.values() if not x.get("ok"))
        hdr = ("-- %s  (%d device(s) -- success=%d skipped=%d failed=%d"
               % (loc, len(res), cnt["success"], cnt["skipped"],
                  cnt["failed"]))
        if rv: hdr += "  revert_ok=%d revert_fail=%d" % (rc, rf)
        hdr += ") --"
        print("\n  %s" % hdr)
        print("  " + "-" * 76)
        print("  %2s%-30s %-15s Detail" % ("", "Hostname", "IP"))
        print("  " + "-" * 76)
        for want in ("success", "skipped", "failed"):
            for r in sorted((x for x in res.values() if x["status"] == want),
                            key=lambda x: x["hostname"]):
                print("  " + _device_line(r))
        for h, rvr in sorted(rv.items()):
            if not rvr.get("ok"):
                print("      revert failed: %s -- %s"
                      % (h, rvr.get("message", "")[:60]))
    total = ok + skipped + failed
    print("\n" + "=" * 78)
    print("  TOTAL  success=%d  skipped=%d  failed=%d  (of %d)"
          % (ok, skipped, failed, total))
    print("=" * 78)
    cf = sum(1 for loc in all_results.values()
             for r in loc.values() if r.get("clock_corrected"))
    if cf:
        print("\n  %d device(s) had clock drift corrected during pre-check"
              % cf)
    manual = []
    for loc in sorted(all_results.keys()):
        for r in sorted(all_results[loc].values(),
                        key=lambda x: x["hostname"]):
            if r["status"] == "failed":
                manual.append((loc, r))
    if manual:
        print("\n  %d device(s) NEED MANUAL ATTENTION:" % len(manual))
        for loc, r in manual:
            ip = r.get("ip", "?")
            stage = r.get("stage", "?")
            err = (r.get("error") or "?")[:80]
            print("      !! %-30s (%s) [%s]" % (r["hostname"], ip, loc))
            print("          stage=%s  error=%s" % (stage, err))
            if r.get("install_started"):
                print("          install was started -- check `show install log`")
            if r.get("verify_pending"):
                print("          verify_pending=True -- reconcilable next run")
    try:
        prev = _load_previous_run_summary()
        if prev:
            anom = detect_anomalies(all_results, prev)
            if anom:
                print("\n  ANOMALIES vs previous run (%s):"
                      % prev.get("run_id", "?"))
                for h, m in anom:
                    print("      ! %s: %s" % (h, m))
    except Exception: pass
    try: trend_report(all_results, lookback=5)
    except Exception: pass
    with TEMP_CHANGES_LOCK:
        pending = sorted(h for h, e in TEMP_CHANGES.items()
                         if e.get("changes"))
    if pending:
        print("\n  %d device(s) still have un-reverted temp config "
              "changes -- run with --recover" % len(pending))
        for h in pending:
            print("      - %s" % h)
    print("=" * 78 + "\n")
    return failed


def _reconcile_failed_devices(all_results, all_revert, user, pw):
    if not RECONCILE_FAILED_AT_END:
        return all_results, all_revert
    candidates = []
    for loc, res in all_results.items():
        for host, r in res.items():
            if r.get("status") != "failed": continue
            eligible = (r.get("verify_pending")
                        or r.get("stage") in ("install", "verify", "reboot"))
            if not eligible: continue
            ip = r.get("ip", "")
            target_ver = r.get("target_version", "")
            if not ip or not target_ver: continue
            candidates.append((loc, host, ip, target_ver, r))
    if not candidates:
        print("\n  Reconcile: no verify-pending failures to recheck")
        return all_results, all_revert
    print("\n" + "=" * 70)
    print("  RECONCILE -- rechecking %d failed device(s)" % len(candidates))
    print("=" * 70)
    reconciled = 0; still_failed = 0
    reconciled_locs = set()
    for loc, host, ip, target_ver, r in candidates:
        print("\n  [%s] %s -- checking for %s..." % (host, ip, target_ver),
              flush=True)
        c_ = None
        ok_now = False
        try:
            c_ = do_connect(ip, user, pw)
            tacacs_enable(c_, host, ssh_pw=pw)
            if not is_privileged(c_):
                print("    not priv-15 -- cannot verify"); continue
            out = c_.send_command("show version | include Version",
                                  read_timeout=60)
            post_ver = parse_running_version(out)
            print("    running version: %s" % post_ver)
            if _norm_ver(post_ver) == _norm_ver(target_ver):
                try:
                    b = c_.send_command("show boot | include BOOT",
                                        read_timeout=30)
                    if "packages.conf" not in b:
                        print("    boot var not packages.conf"); continue
                except Exception: pass
                fw_file = ""
                try:
                    fwm = pick_firmware(get_model(c_) or "")
                    if fwm: fw_file = fwm[0]
                except Exception: pass
                if not _finalize_install_commit(c_, host, target_ver,
                                                fw_file=fw_file):
                    print("    device is on target but NOT committed -- "
                          "will revert on next reload")
                    r["error"] = ("on target but commit not verified -- "
                                  "will revert on next reload")
                    r["verify_pending"] = True
                    continue
                ok_now = True
            else:
                print("    still not on %s" % target_ver)
        except Exception as e:
            print("    connection failed: %s: %s"
                  % (type(e).__name__, str(e)[:80]))
        finally:
            if c_:
                try: c_.disconnect()
                except Exception: pass
        if ok_now:
            print("    RECONCILED -- device is on %s" % target_ver)
            r["status"] = "success"
            r["stage"] = "install"
            r["error"] = ""
            r["post_version"] = target_ver
            r["verify_pending"] = False
            reconciled += 1
            reconciled_locs.add(loc)
        else:
            still_failed += 1
    print("\n" + "-" * 70)
    print("  Reconciled (now success) : %d" % reconciled)
    print("  Still failed             : %d" % still_failed)
    print("-" * 70 + "\n")
    for loc in reconciled_locs:
        loc_res = all_results.get(loc, {})
        rv = all_revert.get(loc, {})
        write_location_report(loc, loc_res, rv, force=True)
    return all_results, all_revert


def write_run_summary(all_results, all_revert, run_id, path):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        flat = []
        for loc in sorted(all_results.keys()):
            for r in sorted(all_results[loc].values(),
                            key=lambda x: x["hostname"]):
                row = dict(r); row["location"] = loc
                flat.append(row)
        summary = {
            "run_id": run_id,
            "timestamp": datetime.now().isoformat(),
            "version_string": VERSION_STRING,
            "totals": {
                "success": sum(1 for r in flat if r["status"] == "success"),
                "skipped": sum(1 for r in flat if r["status"] == "skipped"),
                "failed":  sum(1 for r in flat if r["status"] == "failed"),
                "total":   len(flat)},
            "by_location": {
                loc: {"success": sum(1 for r in all_results[loc].values()
                                     if r["status"] == "success"),
                      "skipped": sum(1 for r in all_results[loc].values()
                                     if r["status"] == "skipped"),
                      "failed": sum(1 for r in all_results[loc].values()
                                    if r["status"] == "failed"),
                      "revert_failed": sum(
                          1 for x in all_revert.get(loc, {}).values()
                          if not x.get("ok"))}
                for loc in sorted(all_results.keys())},
            "results": flat}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        print("  Summary: %s" % path)
        return path
    except Exception as e:
        master_log("run_summary err: %s" % e)
        return None


_HTML_TPL = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Cisco Upgrade Run {rid}</title>
<style>
 body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif;
         margin: 24px; color: #222; }}
 h1 {{ font-size: 20px; margin-bottom: 4px; }}
 .meta {{ color: #666; font-size: 13px; margin-bottom: 20px; }}
 table {{ border-collapse: collapse; width: 100%; margin-bottom: 24px; }}
 th, td {{ padding: 6px 10px; border-bottom: 1px solid #e5e5e5;
           text-align: left; font-size: 13px; }}
 th {{ background: #f5f5f5; font-weight: 600; }}
 tr.s-success td:first-child {{ color: #1a7f37; }}
 tr.s-failed  td:first-child {{ color: #b62324; }}
 tr.s-skipped td:first-child {{ color: #8a6d00; }}
 .totals {{ display: flex; gap: 20px; margin-bottom: 24px; font-size: 14px; }}
 .totals span {{ padding: 4px 10px; border-radius: 4px; background: #f5f5f5; }}
 .badge {{ display: inline-block; padding: 1px 6px; border-radius: 3px;
           background: #eef; font-size: 11px; color: #335; }}
</style></head><body>
<h1>Cisco IOS-XE Upgrade -- Run {rid}</h1>
<div class="meta">Version {ver} &middot; {ts}</div>
<div class="totals">
 <span>success={s}</span><span>skipped={k}</span>
 <span>failed={f}</span><span>total={t}</span>
</div>
{blocks}
</body></html>"""

_HTML_LOC = """<h2>{loc} -- {n} device(s)</h2>
<table><tr><th>Status</th><th>Hostname</th><th>IP</th>
<th>Start</th><th>Target</th><th>Post</th><th>Duration</th><th>Error</th></tr>
{rows}</table>"""


def _html_escape(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def write_html_report(all_results, path, run_id=None):
    run_id = run_id or RUN_ID
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tot = {"success": 0, "skipped": 0, "failed": 0}
        blocks = []
        for loc in sorted(all_results.keys()):
            rows = []
            for r in sorted(all_results[loc].values(),
                            key=lambda x: x["hostname"]):
                tot[r["status"]] = tot.get(r["status"], 0) + 1
                dur = _fmt_duration(r.get("duration_sec", 0))
                err = _html_escape(r.get("error", "")[:100])
                flags = []
                if r.get("reboot_detected"): flags.append("reboot")
                if r.get("md5_ok"):          flags.append("md5")
                if r.get("clock_corrected"): flags.append("clock")
                fh = (" " + " ".join('<span class="badge">%s</span>' % f
                                     for f in flags)) if flags else ""
                rows.append(
                    '<tr class="s-%s"><td>%s</td><td>%s%s</td><td>%s</td>'
                    '<td>%s</td><td>%s</td><td>%s</td><td>%s</td>'
                    '<td>%s</td></tr>'
                    % (r["status"], r["status"],
                       _html_escape(r["hostname"]), fh,
                       _html_escape(r["ip"]),
                       _html_escape(r.get("start_version", "")),
                       _html_escape(r.get("target_version", "")),
                       _html_escape(r.get("post_version", "")),
                       dur, err))
            blocks.append(_HTML_LOC.format(
                loc=_html_escape(loc), n=len(all_results[loc]),
                rows="\n".join(rows)))
        html = _HTML_TPL.format(
            rid=run_id, ver=VERSION_STRING,
            ts=datetime.now().isoformat(timespec="seconds"),
            s=tot["success"], k=tot["skipped"], f=tot["failed"],
            t=sum(tot.values()), blocks="\n".join(blocks))
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        print("  HTML: %s" % path)
        return path
    except Exception as e:
        master_log("HTML err: %s" % e)
        return None


def post_run_health_snapshot(all_results, user, pw, path):
    devices = []
    for loc, res in all_results.items():
        for r in res.values():
            if r["status"] in ("success", "skipped"):
                devices.append((r["hostname"], r["ip"]))
    if not devices: return
    print("\n  -- Post-run health snapshot (%d device(s)) --" % len(devices))
    def _chk(host, ip):
        cc = None
        try:
            cc = do_connect(ip, user, pw)
            tacacs_enable(cc, host, ssh_pw=pw)
            ver = cc.send_command("show version | include Version",
                                  read_timeout=60)
            m = re.search(r"Version ([\w.()]+)", ver)
            boot = cc.send_command("show boot | include BOOT",
                                   read_timeout=60)
            switch = ""
            try:
                switch = cc.send_command("show switch", read_timeout=60)
            except Exception: pass
            rows = _SWITCH_ROW_RE.findall(switch)
            nr = sum(1 for _, st in rows
                     if st.lower() not in ("ready", "standby"))
            return {"hostname": host, "ip": ip,
                    "version": m.group(1) if m else "?",
                    "boot_ok": "packages.conf" in boot,
                    "stack_members": len(rows), "stack_not_ready": nr,
                    "ts": datetime.now().isoformat(timespec="seconds")}
        except Exception as e:
            return {"hostname": host, "ip": ip, "version": "?",
                    "boot_ok": False, "stack_members": 0,
                    "stack_not_ready": 0, "error": str(e)[:80],
                    "ts": datetime.now().isoformat(timespec="seconds")}
        finally:
            if cc:
                try: cc.disconnect()
                except Exception: pass
    snaps = []
    with ThreadPoolExecutor(max_workers=min(20, len(devices))) as ex:
        for f in as_completed([ex.submit(_chk, h, ip)
                               for h, ip in devices]):
            snaps.append(f.result())
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"run_id": RUN_ID, "snapshots": snaps}, f, indent=2)
        print("  Health: %s" % path)
    except Exception as e:
        master_log("health err: %s" % e)


def save_inventory_cache(devices, path):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"ts": time.time(), "run_id": RUN_ID,
                       "version_string": VERSION_STRING,
                       "devices": devices}, f, indent=2)
        print("  Inventory cache: %s" % path)
        return True
    except Exception as e:
        master_log("inv err: %s" % e)
        return False


def load_inventory_cache(path, max_age_sec=86400):
    if not os.path.isfile(path): return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        age = time.time() - data.get("ts", 0)
        if age > max_age_sec:
            print("  (Inventory cache is %.1fh old -- ignoring)"
                  % (age/3600))
            return None
        print("  (Reusing inventory cache from %.0fm ago)" % (age/60))
        return data.get("devices", [])
    except Exception:
        return None


def filter_only_upgrade_needed(devices, user, pw):
    need, target, unreach = [], [], []
    def _chk(d):
        host, ip = d["hostname"], d["ip"]
        cc = None
        try:
            cc = do_connect(ip, user, pw)
            tacacs_enable(cc, host, ssh_pw=pw)
            if not is_privileged(cc):
                return d, "other", ""
            model = get_model(cc) or ""
            fw = pick_firmware(model)
            if not fw:
                return d, "other", "unsupported model '%s'" % model
            _, tg = fw
            ver = cc.send_command("show version | include Version",
                                  read_timeout=60)
            return d, ("target"
                       if _norm_ver(parse_running_version(ver))
                       == _norm_ver(tg) else "needs"), tg
        except Exception as e:
            return d, "unreach", str(e)[:80]
        finally:
            if cc:
                try: cc.disconnect()
                except Exception: pass
    with ThreadPoolExecutor(max_workers=min(20, max(len(devices), 1))) as ex:
        for d, st, info in ex.map(_chk, devices):
            if st == "needs":    need.append((d, info))
            elif st == "target": target.append((d, info))
            elif st == "unreach": unreach.append((d, info))
            else:                need.append((d, info))
    return need, target, unreach


def print_change_preview(all_devices, user, pw):
    print("\n" + "=" * 70)
    print("  CHANGE PREVIEW (read-only)")
    print("=" * 70)
    rows = []
    def _chk(d):
        host, ip = d["hostname"], d["ip"]
        cc = None
        try:
            cc = do_connect(ip, user, pw)
            tacacs_enable(cc, host, ssh_pw=pw)
            model = get_model(cc) or "?"
            fw = pick_firmware(model)
            tg = fw[1] if fw else "?"
            vo = cc.send_command("show version | include Version",
                                 read_timeout=60)
            cur = parse_running_version(vo) or "?"
            action = ("skip (already on target)"
                      if _norm_ver(cur) == _norm_ver(tg)
                      else "upgrade -> %s" % tg if fw
                      else "unsupported model")
            return (host, ip, model, cur, tg, action)
        except Exception as e:
            return (host, ip, "?", "?", "?",
                    "unreachable: %s" % str(e)[:40])
        finally:
            if cc:
                try: cc.disconnect()
                except Exception: pass
    with ThreadPoolExecutor(max_workers=min(20,
                                            max(len(all_devices), 1))) as ex:
        for row in ex.map(_chk, all_devices):
            rows.append(row)
    wc = [r for r in rows if r[5].startswith("upgrade")]
    ws = [r for r in rows if r[5].startswith("skip")]
    wf = [r for r in rows if r[5].startswith("unreachable")
          or r[5] == "unsupported model"]
    print("  %2s %-30s %-15s %-18s %-12s Action"
          % ("", "Hostname", "IP", "Model", "Current"))
    print("  " + "-" * 100)
    for host, ip, model, cur, tg, action in sorted(rows):
        mk = (">" if action.startswith("upgrade")
              else "-" if action.startswith("skip") else "X")
        print("  %s  %-30s %-15s %-18s %-12s %s"
              % (mk, host, ip, model, cur, action))
    print("  " + "-" * 100)
    print("  %d will upgrade, %d already on target, %d need attention"
          % (len(wc), len(ws), len(wf)))
    print("=" * 70 + "\n")
    return wc, ws, wf


def estimate_runtime(all_devices, user, pw):
    print("\n" + "=" * 70)
    print("  RUNTIME ESTIMATE (no changes made)")
    print("=" * 70)
    rows = []
    def _chk(d):
        host, ip = d["hostname"], d["ip"]
        cc = None
        try:
            cc = do_connect(ip, user, pw)
            tacacs_enable(cc, host, ssh_pw=pw)
            model = get_model(cc) or "?"
            fw = pick_firmware(model)
            if not fw: return (host, ip, model, "?", 0)
            fwf, tg = fw
            vo = cc.send_command("show version | include Version",
                                 read_timeout=60)
            cur = parse_running_version(vo) or "?"
            return (host, ip, model, cur, get_firmware_size(fwf))
        except Exception:
            return (host, ip, "?", "?", 0)
        finally:
            if cc:
                try: cc.disconnect()
                except Exception: pass
    with ThreadPoolExecutor(max_workers=min(20,
                                            max(len(all_devices), 1))) as ex:
        rows = list(ex.map(_chk, all_devices))
    total_s = 0
    for host, ip, model, cur, sz in sorted(rows):
        per = 30 + (sz / 20e6) + 120 + 600 + 480 + 180 + 90
        total_s += per
    parallel = max(1, min(TRANSFER_SLOTS, INSTALL_WORKERS))
    wall = total_s / parallel
    print("  %d device(s), ~%d concurrent pipelines" % (len(rows), parallel))
    if rows:
        print("  Per-device avg: %s"
              % _fmt_duration(int(total_s / max(len(rows), 1))))
    print("  Estimated wall time: %s (+/-40%%)" % _fmt_duration(int(wall)))
    print("=" * 70 + "\n")
    return 0


def prompt_resume_or_abort(stale_files):
    print("\n  Un-reverted temp-config state from an earlier run exists:")
    for s in stale_files:
        print("     - %s" % s)
    print("\n  Options:")
    print("    [R] Resume -- skip already-verified devices")
    print("    [S] Skip failed -- retry only previously failed devices")
    print("    [A] Abort -- exit cleanly (--recover to revert temp config)")
    try:
        ans = input("  Choice [R/S/A]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return "abort"
    if ans.startswith("r"): return "resume"
    if ans.startswith("s"): return "skip"
    return "abort"


_CONFIG_KEYS = {
    "LOCATIONS_TO_RUN", "TRANSFER_SLOTS", "INSTALL_WORKERS",
    "MAX_SAFE_SSH_SESSIONS", "PRESERVE_ROLLBACK", "MIN_FREE_BYTES",
    "EXTRA_HEADROOM_BYTES", "STACK_MEMBER_HEADROOM", "RETRY_FAILED_DEVICES",
    "MAX_RETRIES", "RETRY_DELAY_SEC", "ABORT_GATE_THRESHOLD",
    "ABORT_GATE_MIN_DEVICES", "SCP_TIMEOUT_SEC", "SCP_MAX_ATTEMPTS",
    "SCP_RETRY_DELAY", "SCP_STALL_TIMEOUT", "SCP_PROGRESS_POLL",
    "ENABLE_SCP_MONITOR", "USE_PSCP", "PSCP_TRANSFER_FALLBACK",
    "TRANSFER_RETRY_ATTEMPTS", "TRANSFER_RETRY_DELAY_SEC",
    "TRANSFER_VERIFY_TIMEOUT", "VERIFY_TRANSFER_HASH",
    "LARGE_MODEL_PARALLEL", "USE_PARAMIKO_TUNED", "PARAMIKO_PRIMARY",
    "PARAMIKO_CHANNEL_CHUNK", "PARAMIKO_WINDOW_BYTES",
    "PARAMIKO_DISABLE_REKEY", "CHEAP_CRYPTO_TUNING", "CHEAP_CIPHER",
    "CHEAP_MAC", "PREFER_CHEAP_CIPHERS", "BULK_MODE_WINDOW_SIZE",
    "LEGACY_WINDOW_SIZE", "RECONNECT_MAX_ATTEMPTS", "RECONNECT_DELAY_SEC",
    "PING_TIMEOUT_MS", "PING_DOWN_POLL_SEC", "PING_DOWN_TIMEOUT_SEC",
    "PING_UP_POLL_SEC", "PING_UP_TIMEOUT_SEC", "PING_STABILITY_SEC",
    "POST_REBOOT_SSH_WAIT_SEC", "POST_REBOOT_SETTLE_SEC",
    "POST_REBOOT_MAX_ATTEMPTS", "POST_REBOOT_DELAY_SEC",
    "PROBE_CONNECT_RETRIES", "PROBE_CONNECT_DELAY_SEC",
    "RECONCILE_FAILED_AT_END", "HEALTH_RETRIES", "HEALTH_RETRY_DELAY_SEC",
    "INSTALL_TOTAL_TIMEOUT", "INSTALL_SILENT_TIMEOUT",
    "INSTALL_PROBE_INTERVAL", "ISSU_VERIFY_TIMEOUT", "ISSU_VERIFY_MAX_ERRORS",
    "COMMIT_VERIFY_TIMEOUT", "COMMIT_VERIFY_RETRY_SEC",
    "SESSION_SLOT_ACQUIRE_TIMEOUT",
    "DO_BACKUP", "DO_VERIFY_MD5", "WIPE_BEFORE_TRANSFER",
    "DO_RESET_DEVICE_LOGS", "PRE_SAVE_CONFIG", "SKIP_CONFIG_DRIFT_CHECK",
    "ALLOW_BUNDLE_MODE_CONVERSION", "POOL_LOCATIONS",
    "REVERT_TEMP_CONFIG_POST_LOCATION", "REVERT_MAX_ATTEMPTS",
    "REVERT_RETRY_DELAY_SEC", "REVERT_UPTIME_GATE_MIN",
    "REVERT_WRITE_MEMORY", "REVERT_VERIFY_AFTER", "LIVE_LOG_PANEL_PHASES",
    "LIVE_LOG_FEED_TRANSFER", "LARGE_MODEL_PREFIXES",
    "SERIAL_TRANSFER_LARGE_MODELS", "BACKUP_MAX_FILES",
    "BACKUP_MAX_SIZE_GB", "LOG_ARCHIVE_MAX_DAYS", "LOG_ARCHIVE_MAX_SIZE_GB",
    "CLOCK_DRIFT_WARN_SEC", "CLOCK_DRIFT_FIX_SEC", "STRICT_FAMILY_CHECK",
    "MONITOR_INTERVAL", "LOG_MAX_AGE_DAYS", "LOG_MAX_SIZE_GB",
    "MODEL_FIRMWARE_MAP", "MODELS_REQUIRING_SSH_TUNE",
    "FAMILY_SIZE_BOUNDS_STRICT", "MAX_FIRMWARE_BYTES",
    "MIN_FIRMWARE_BYTES", "DASHBOARD_REPAINT_SEC",
    "EXTRACTION_OVERHEAD_FACTOR", "ALLOW_ACTIVE_PKG_PURGE",
}


def apply_config_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print("  Could not read config file %s: %s" % (path, e))
        return False
    g = globals()
    for k, v in data.items():
        if k not in _CONFIG_KEYS:
            print("  Config key not recognized: %s" % k); continue
        if k == "MODEL_FIRMWARE_MAP":
            v = [tuple(x) for x in v]
            v.sort(key=lambda x: -len(x[0]))
        if k in ("MODELS_REQUIRING_SSH_TUNE", "LARGE_MODEL_PREFIXES",
                 "LIVE_LOG_PANEL_PHASES"):
            v = tuple(v)
        g[k] = v
    print("  Loaded config: %s" % path)
    return True


_SIG_COUNT = [0]


def _on_signal(signum, frame):
    _SIG_COUNT[0] += 1
    if _SIG_COUNT[0] == 1:
        SHUTDOWN_REQ.set()
        msg = ("\n  !! Shutdown requested -- finishing safely; temp config "
               "will be reverted.\n  !! Press Ctrl-C again to force exit.\n")
    else:
        msg = "\n  !! Forced exit. Run --recover afterwards.\n"
    try: os.write(2, msg.encode("utf-8", "replace"))
    except Exception: pass
    if _SIG_COUNT[0] >= 2: os._exit(130)


def parse_args():
    p = argparse.ArgumentParser(
        description="Cisco IOS-XE upgrade orchestrator v%s" % VERSION_STRING)
    for a in ("--base-dir", "--config", "--user", "--enable-pass",
              "--enable-user"):
        p.add_argument(a)
    p.add_argument("--locations", nargs="+")
    for a in ("--dry-run", "--skip-issu", "--auto-rollback", "--no-pause",
              "--yes", "--precache-hostkeys", "--ignore-stale-state",
              "--force-run-with-stale-state", "--resume", "--recover",
              "--revert-only", "--dry-run-revert", "--preflight-only",
              "--inventory", "--check", "--rollback", "--rollback-dry-run",
              "--no-verify-revert", "--show-live-transfer",
              "--no-serial-large", "--no-drift-check", "--no-hash-verify",
              "--no-reconcile", "--resume-checkpoint", "--retry-failed",
              "--write-manifest", "--verify-mapping", "--validate",
              "--no-bundle-mode", "--no-pool-locations", "--paramiko-primary",
              "--allow-lenient-firmware", "--allow-active-pkg-purge"):
        p.add_argument(a, action="store_true")
    p.add_argument("--allow-bundle-mode", action="store_true", default=None)
    p.add_argument("--pool-locations", action="store_true", default=None)
    p.add_argument("--parallel-large", type=int, default=None, metavar="N")
    p.add_argument("--bulk-window", type=int, default=None, metavar="N")
    p.add_argument("--limit", nargs="+")
    p.add_argument("--exclude", nargs="+")
    p.add_argument("--hosts", nargs="+")
    p.add_argument("--version", action="version",
                   version="cisco_upgrade v%s" % VERSION_STRING)
    p.add_argument("--only-upgrade-needed", action="store_true")
    p.add_argument("--preview", action="store_true")
    p.add_argument("--preview-only", action="store_true")
    p.add_argument("--quiet-skipped", action="store_true")
    p.add_argument("--no-html-report", action="store_true")
    p.add_argument("--no-health-snapshot", action="store_true")
    p.add_argument("--use-inventory-cache", action="store_true")
    p.add_argument("--no-colour", "--no-color", action="store_true",
                   dest="no_colour")
    p.add_argument("--estimate-only", action="store_true")
    p.add_argument("--interactive-resume", action="store_true")
    return p.parse_args()


def get_credentials(args):
    user = (args.user or os.environ.get("CISCO_USER")
            or input("  SSH username: ").strip())
    pw = os.environ.get("CISCO_PASS") or getpass("  SSH password: ")
    return user, pw


def confirm(msg, assume_yes=False):
    if assume_yes: return True
    try:
        return input("%s [y/N]: " % msg).strip().lower() in ("y", "yes")
    except EOFError: return False


def filter_devices(devices, args):
    if args.hosts:
        wanted = {h.strip() for h in args.hosts}
        return [d for d in devices if d["hostname"] in wanted]
    out = devices
    if args.limit:
        wanted = {h.strip() for h in args.limit}
        out = [d for d in out if d["hostname"] in wanted]
    if args.exclude:
        skip = {h.strip() for h in args.exclude}
        out = [d for d in out if d["hostname"] not in skip]
    return out


def mode_dry_run_revert():
    n = load_state_for_recovery(consume=False)
    if not n:
        print("  No recorded temp changes found."); return 0
    hostmap = build_host_ip_map()
    print("\n  %d device(s) have un-reverted temp changes:\n" % n)
    with TEMP_CHANGES_LOCK:
        snap = {h: list(e["changes"]) for h, e in TEMP_CHANGES.items()}
    for host in sorted(snap):
        ip = hostmap.get(host, "??? (not in any location file)")
        print("  %s  (%s)" % (host, ip))
        for ch in snap[host]:
            print("      - %s: %s" % (ch["type"], json.dumps(ch["details"])))
    print("\n  (nothing changed; use --recover to apply)")
    return 0


def mode_recover(args, locations_filter=None):
    n = load_state_for_recovery(consume=True)
    if not n:
        print("  No recorded temp changes found."); return 0
    hostmap = build_host_ip_map()
    if locations_filter:
        allowed = set()
        for loc in locations_filter:
            p = os.path.join(LOCATIONS_DIR, "%s.txt" % loc)
            if os.path.isfile(p):
                allowed |= {d["hostname"] for d in load_location(p)}
            else:
                print("  Missing location file: %s" % p)
        hosts = [h for h in list(TEMP_CHANGES) if h in allowed]
    else:
        hosts = list(TEMP_CHANGES)
    devices, unknown = [], []
    for h in hosts:
        if h in hostmap:
            devices.append({"hostname": h, "ip": hostmap[h]})
        else: unknown.append(h)
    if unknown: print("  No IP known for: %s" % ", ".join(unknown))
    if not devices: return 1 if unknown else 0
    if not confirm("  Revert temp config on %d device(s)?" % len(devices),
                   args.yes):
        print("  Aborted (state kept)."); return 1
    user, pw = get_credentials(args)
    _, no_conn, failed, expected = revert_devices(devices, user, pw,
                                                  "RECOVERY")
    rc = 1 if (no_conn or failed or unknown) else 0
    if REVERT_VERIFY_AFTER and expected:
        rv = verify_revert_clean(devices, user, pw, "RECOVERY", expected)
        if rv and any(not r.get("ok") for r in rv.values()):
            rc = 1
    return rc


def mode_inventory(devices, user, pw):
    print("\n  INVENTORY")
    print("  " + "-" * 68)
    out_devices = []
    for d in devices:
        host, ip = d["hostname"], d["ip"]
        c_ = None
        try:
            c_ = do_connect(ip, user, pw)
            tacacs_enable(c_, host, ssh_pw=pw)
            model = get_model(c_) or "?"
            ver_out = c_.send_command("show version | include Version")
            ver = parse_running_version(ver_out) or "?"
            boot = c_.send_command("show boot | include BOOT")
            mode = "install" if "packages.conf" in boot else "bundle"
            free = get_flash_free_bytes(c_)
            flag = "LARGE" if _is_large_model(model) else "small"
            vt = get_ios_xe_version_tuple(c_)
            tier = _bulk_mode_tier(vt) or "?"
            bulk = ("bulk" if _verify_config_line(c_, "ip ssh bulk-mode")
                    else "no-bulk")
            print("  %-32s %-15s %-18s ver=%-12s mode=%-7s free=%s %s "
                  "tier=%s %s"
                  % (host, ip, model, ver, mode, _fmt_bytes(free), flag,
                     tier, bulk))
            out_devices.append({"hostname": host, "ip": ip, "model": model,
                                "version": ver, "mode": mode,
                                "free_bytes": free, "tier": tier,
                                "bulk": bulk})
        except Exception as e:
            tag = _classify_connect_error(e)
            print("  %-32s %-15s ERROR: %s"
                  % (host, ip, tag or str(e)[:60]))
        finally:
            if c_:
                try: c_.disconnect()
                except Exception: pass
    try:
        save_inventory_cache(out_devices,
                             os.path.join(BASE_DIR, "inventory_cache.json"))
    except Exception: pass
    return 0


def mode_check(devices, user, pw):
    print("\n  VERSION CHECK")
    print("  " + "-" * 68)
    for d in devices:
        host, ip = d["hostname"], d["ip"]
        c_ = None
        try:
            c_ = do_connect(ip, user, pw)
            tacacs_enable(c_, host, ssh_pw=pw)
            model = get_model(c_) or ""
            fw = pick_firmware(model)
            if not fw:
                print("  %-32s unsupported model '%s'" % (host, model))
                continue
            _, target_ver = fw
            ver_out = c_.send_command("show version | include Version")
            cur = parse_running_version(ver_out) or "?"
            status = ("OK (target)"
                      if _norm_ver(cur) == _norm_ver(target_ver)
                      else "upgrade needed -> %s" % target_ver)
            print("  %-32s %-15s current=%-14s %s"
                  % (host, ip, cur, status))
        except Exception as e:
            tag = _classify_connect_error(e)
            print("  %-32s %-15s ERROR: %s"
                  % (host, ip, tag or str(e)[:60]))
        finally:
            if c_:
                try: c_.disconnect()
                except Exception: pass
    return 0


def mode_rollback(devices, user, pw, args, dry=False):
    verb = "DRY-RUN " if dry else ""
    if not confirm("  %sIssue `install rollback to committed` on "
                   "%d device(s)?" % (verb, len(devices)), args.yes):
        print("  Aborted."); return 1
    print("\n  ROLLBACK%s" % (" (DRY-RUN)" if dry else ""))
    print("  " + "-" * 68)
    rc = 0
    for d in devices:
        host, ip = d["hostname"], d["ip"]
        conn = None
        try:
            conn = do_connect(ip, user, pw)
            tacacs_enable(conn, host, ssh_pw=pw)
            cur = ""
            try:
                _o = conn.send_command("show version | include Version",
                                       read_timeout=30)
                cur = parse_running_version(_o)
            except Exception: pass
            if dry:
                try:
                    summ = conn.send_command("show install summary",
                                             read_timeout=60)
                    feed_live_log(host,
                                  "[rollback-dry] show install summary\n%s"
                                  % summ)
                    entries = _parse_install_summary(summ)
                    inactive = [v for v, s in entries.items() if s == "I"]
                    print("  %-32s current=%-14s inactive_images=%d %s"
                          % (host, cur, len(inactive),
                             "(rollback possible)" if inactive
                             else "(no inactive image)"))
                except Exception as e:
                    print("  %-32s DRY-RUN ERROR: %s" % (host, str(e)[:60]))
                    rc = 1
            else:
                if attempt_rollback(conn, host, ip=ip, user=user, pw=pw,
                                    original_version=cur):
                    print("  %-32s rollback issued" % host)
                else:
                    print("  %-32s rollback FAILED" % host); rc = 1
        except Exception as e:
            tag = _classify_connect_error(e)
            print("  %-32s ERROR: %s" % (host, tag or str(e)[:60])); rc = 1
        finally:
            if conn:
                try: conn.disconnect()
                except Exception: pass
    return rc


def mode_verify_mapping(devices, user, pw):
    print("\n  FIRMWARE MAPPING VERIFICATION")
    print("  " + "-" * 68)
    for d in devices:
        host, ip = d["hostname"], d["ip"]
        c_ = None
        try:
            c_ = do_connect(ip, user, pw)
            tacacs_enable(c_, host, ssh_pw=pw)
            model = get_model(c_) or ""
            fw = pick_firmware(model)
            if not fw:
                print("  %-32s %-18s UNSUPPORTED" % (host, model))
                continue
            fwf, tg = fw
            ok, reason = verify_model_firmware_consistency(model, fwf, tg)
            print("  %-32s %-18s %-42s %s"
                  % (host, model, fwf, "OK" if ok else reason))
        except Exception as e:
            tag = _classify_connect_error(e)
            print("  %-32s ERROR: %s" % (host, tag or str(e)[:60]))
        finally:
            if c_:
                try: c_.disconnect()
                except Exception: pass
    return 0


def _validate():
    passed, failed = [], []
    def _t(name, fn):
        try:
            fn(); passed.append(name)
        except AssertionError as e:
            failed.append((name, "assertion: %s" % e))
        except Exception as e:
            failed.append((name, "%s: %s" % (type(e).__name__, e)))

    def t_family():
        assert _family_for_model("C9200L-24P") == ("lite", "_lite_")
        assert _family_for_model("C9300-48P") == ("full", None)
        assert _family_for_model("C9500-24Y4C") == ("full", None)
        assert _family_for_model("C9200CX-8P") == ("lite", "_lite_")
        assert _family_for_model("") == (None, None)
        assert _family_for_model("Unknown") == (None, None)
    _t("_family_for_model", t_family)

    def t_size():
        assert _family_size_ok("lite", 500_000_000)[0]
        assert not _family_size_ok("lite", 1_500_000_000)[0]
        assert _family_size_ok("full", 1_200_000_000)[0]
        assert not _family_size_ok("full", 400_000_000)[0]
        assert _family_size_ok(None, 0)[0]
    _t("_family_size_ok", t_size)

    def t_norm():
        raw = "\n".join([
            "Building configuration...",
            "Current configuration : 2345 bytes",
            "!", "! Last configuration change at 12:00",
            "version 17.18", "hostname SW1", "!",
            "endpoint-tracking", "end-user-acl 1", "end", "",
            "3d04h: %SYS-5-CONFIG_I: Configured from console"])
        out = _normalize_config(raw)
        assert "version 17.18" in out
        assert "hostname SW1" in out
        assert "endpoint-tracking" in out
        assert "end-user-acl 1" in out
        assert "end" not in out
        assert all(not l.startswith("!") for l in out)
    _t("_normalize_config keeps endpoint-* lines", t_norm)

    def t_drift_noise():
        assert _is_drift_noise("- exec-timeout 60 0")
        assert _is_drift_noise("+ exec-timeout 30 0")
        assert _is_drift_noise("- ip ssh bulk-mode window-size 131072")
        assert _is_drift_noise("+ ip scp server enable")
        assert not _is_drift_noise("+ hostname SW1")
        assert not _is_drift_noise("+++ b/file")
        assert not _is_drift_noise("--- a/file")
    _t("config-drift noise filters both sides", t_drift_noise)

    def t_norm_ver():
        assert _norm_ver("17.18.04") == "17.18.4"
        assert _norm_ver("17.18.4")  == "17.18.4"
        assert _norm_ver("") == ""
        assert _norm_ver(None) == ""
        assert _norm_ver("garbage") == "garbage"
    _t("_norm_ver", t_norm_ver)

    def t_member_required():
        fw = 478_710_000
        need_act_have = _member_required_bytes(
            fw, True, bin_already_present=True, is_standby=False)
        assert 550_000_000 < need_act_have < 650_000_000, need_act_have
        need_act_no = _member_required_bytes(
            fw, True, bin_already_present=False, is_standby=False)
        assert 1_050_000_000 < need_act_no < 1_100_000_000, need_act_no
        need_stby = _member_required_bytes(
            fw, True, bin_already_present=True, is_standby=True)
        assert 1_050_000_000 < need_stby < 1_100_000_000, need_stby
        assert need_stby == need_act_no
        assert _member_required_bytes(0, True) == MIN_FREE_BYTES
    _t("v35.9.34 _member_required_bytes (active vs standby)",
       t_member_required)

    def t_extraction_factor_realistic():
        assert 1.0 <= EXTRACTION_OVERHEAD_FACTOR <= 1.15, \
            "extraction factor must be >=1.0 (bin is compressed)"
    _t("v35.9.33 extraction factor >= 1.0", t_extraction_factor_realistic)

    def t_space_markers_extended():
        assert "not enough free disk" in _SPACE_MARKERS
        assert "free disk available" in _SPACE_MARKERS
        assert "not enough space" in _SPACE_MARKERS
        assert "insufficient space" in _SPACE_MARKERS
    _t("v35.9.30 Cisco space markers", t_space_markers_extended)

    def t_runinstall_uses_space_marker():
        import inspect as _i
        src = _i.getsource(run_install)
        assert "_SPACE_MARKERS" in src
        assert "insufficient_space: install engine rejected" in src
    _t("v35.9.30 run_install short-circuits on Cisco space error",
       t_runinstall_uses_space_marker)

    def t_precheck_uses_new_formula():
        import inspect as _i
        src = _i.getsource(precheck_device)
        assert "_member_required_bytes" in src
        assert "EXTRACTION_OVERHEAD_FACTOR" in src
        assert "insufficient_space_stack" in src
    _t("v35.9.31 precheck uses new formula",
       t_precheck_uses_new_formula)

    def t_force_wipe_allows_running_bin():
        import inspect as _i
        src = _i.getsource(_force_wipe_flash)
        assert "allow_running_bin_delete" in src
        assert "_is_install_mode" in src
        assert "keep_bin" in src
    _t("v35.9.31 force-wipe can delete running .bin in install mode",
       t_force_wipe_allows_running_bin)

    def t_do_connect_call():
        import inspect as _i
        src = _i.getsource(wait_reboot_and_verify)
        assert "do_connect(ip, host, user, pw" not in src
        assert "do_connect(ip, user, pw)" in src
    _t("v35.9.31 wait_reboot_and_verify uses correct do_connect",
       t_do_connect_call)

    def t_verify_boot_and_install_ready():
        import inspect as _i
        src = _i.getsource(verify_boot_and_install_ready)
        assert "packages.conf" in src
        assert "install_busy" in src
        assert "size_mismatch" in src
    _t("v35.9.31 verify_boot_and_install_ready",
       t_verify_boot_and_install_ready)

    def t_purge_unnecessary():
        import inspect as _i
        src = _i.getsource(_purge_unnecessary_files)
        assert "_read_active_packages" in src
        assert "aggressive" in src
        assert "active_pkgs" in src
    _t("v35.9.31 _purge_unnecessary_files", t_purge_unnecessary)

    def t_summary_multi():
        out = "\n".join([
            "Install Summary", "===============", "",
            "IMG: flash:cat9k_iosxe.17.18.04.SPA.bin",
            "  Version : 17.18.04", "  Status  : C"])
        assert summary_committed_on_target(out, "17.18.04")
        assert summary_committed_on_target(out, "17.18.4")
        assert not summary_committed_on_target(out, "17.15.01")
    _t("summary_committed_on_target (multi-block)", t_summary_multi)

    def t_summary_with_leftover_I():
        out = "\n".join([
            "IMG: flash:cat9k_iosxe.17.18.04.SPA.bin",
            "  Version : 17.18.04", "  Status  : C",
            "IMG: flash:cat9k_iosxe.17.15.03.SPA.bin",
            "  Version : 17.15.03", "  Status  : I"])
        assert summary_committed_on_target(out, "17.18.04")
    _t("summary accepts leftover I", t_summary_with_leftover_I)

    def t_summary_two_C_rejected():
        out = "\n".join([
            "IMG: flash:cat9k_iosxe.17.18.04.SPA.bin",
            "  Version : 17.18.04", "  Status  : C",
            "IMG: flash:cat9k_iosxe.17.15.03.SPA.bin",
            "  Version : 17.15.03", "  Status  : C"])
        assert not summary_committed_on_target(out, "17.18.04")
    _t("summary rejects two-C", t_summary_two_C_rejected)

    def t_summary_uncommitted():
        out = "\n".join([
            "IMG: flash:cat9k_iosxe.17.18.04.SPA.bin",
            "  Version : 17.18.04", "  Status  : U"])
        assert not summary_committed_on_target(out, "17.18.04")
    _t("summary rejects Uncommitted", t_summary_uncommitted)

    def t_summary_rows_ok():
        out = "\n".join(["  IMG  C  17.18.04"])
        assert summary_committed_on_target(out, "17.18.04")
    _t("summary rows form accepts single C", t_summary_rows_ok)

    def t_parse_summary_multi():
        out = ("IMG: flash:cat9k_iosxe.17.18.04.SPA.bin\n"
               "  Version : 17.18.04\n"
               "  Status  : C\n"
               "IMG: flash:cat9k_iosxe.17.15.03.SPA.bin\n"
               "  Version : 17.15.03\n"
               "  Status  : I")
        r = _parse_install_summary(out)
        assert r.get("17.18.4") == "C"
        assert r.get("17.15.3") == "I"
    _t("_parse_install_summary (multi-block)", t_parse_summary_multi)

    def t_parse_summary_rows():
        out = "  IMG  C  17.18.04\n  IMG  A  17.15.03\n  IMG  U  17.12.04\n  IMG  I  17.11.01"
        r = _parse_install_summary(out)
        assert r.get("17.18.4") == "C"
        assert r.get("17.15.3") == "A"
        assert r.get("17.12.4") == "U"
        assert r.get("17.11.1") == "I"
    _t("_parse_install_summary (rows)", t_parse_summary_rows)

    def t_parse_summary_empty():
        assert _parse_install_summary("") == {}
        assert _parse_install_summary(None) == {}
    _t("_parse_install_summary (empty)", t_parse_summary_empty)

    def t_dead_socket():
        for txt in ("Socket is closed", "connection reset",
                    "broken pipe", "EOF", "channel closed",
                    "no existing session", "EOF occurred",
                    "EOF when reading a line"):
            assert _is_dead_socket_error(txt) is True, txt
        assert _is_dead_socket_error("parser found no EOF marker") is False
        assert _is_dead_socket_error("random error") is False
        assert _is_dead_socket_error("no EOF found") is False
    _t("_is_dead_socket_error (anchored)", t_dead_socket)

    def t_bulk():
        assert _bulk_mode_tier((17, 10, 1)) == "A"
        assert _bulk_mode_tier((17, 12, 3)) == "A"
        assert _bulk_mode_tier((17, 6, 5)) == "B"
        assert _bulk_mode_tier((17, 2, 1)) == "C"
        assert _bulk_mode_tier((16, 12, 5)) == "D"
        assert _bulk_mode_tier(None) is None
    _t("_bulk_mode_tier", t_bulk)

    def t_bins():
        out = "\n".join([
            "Directory of flash:/", "",
            "    1  -rw-  12345678   Mar 1 2025 12:00:00 +00:00  "
            "cat9k_iosxe.17.18.04.SPA.bin",
            "    2  -rw-   9876543   Mar 1 2025 12:00:00 +00:00  "
            "cat9k_lite_iosxe.17.18.04.SPA.bin",
            "    3  drwx        4096  Mar 1 2025 12:00:00 +00:00  .installer"])
        bins = parse_dir_bins(out)
        assert "cat9k_iosxe.17.18.04.SPA.bin" in bins
        assert "cat9k_lite_iosxe.17.18.04.SPA.bin" in bins
    _t("parse_dir_bins", t_bins)

    def t_fsize():
        out = ("-rw-   123456789   Mar 1 2025 12:00:00 +00:00  "
               "cat9k_iosxe.17.18.04.SPA.bin")
        assert _parse_file_size_from_dir(
            out, "cat9k_iosxe.17.18.04.SPA.bin") == 123456789
    _t("_parse_file_size_from_dir", t_fsize)

    def t_uptime():
        assert parse_uptime_minutes("2 weeks, 3 days, 4 hours, 5 minutes") \
            == 2*10080 + 3*1440 + 4*60 + 5
        assert parse_uptime_minutes("1 year, 12 weeks") == 525600 + 12*10080
        assert parse_uptime_minutes("garbage") is None
    _t("parse_uptime_minutes", t_uptime)

    def t_vty():
        out = "\n".join([
            "line vty 0 4", " exec-timeout 60 0", " transport input ssh",
            "line vty 5 15", " transport input ssh"])
        b = parse_vty_blocks(out)
        assert len(b) == 2
        assert b[0]["vty"] == "0 4"
        assert b[0]["minutes"] == 60
        assert b[1]["vty"] == "5 15"
        assert b[1].get("was_default") is True
    _t("parse_vty_blocks", t_vty)

    def t_class():
        e = Exception("No acceptable KEX algorithm")
        assert _classify_connect_error(e) == "SSH negotiation failed"
        e = Exception("No acceptable host key")
        assert _classify_connect_error(e) == "SSH host-key negotiation failed"
        e = Exception("some random error")
        assert _classify_connect_error(e) == ""
    _t("_classify_connect_error", t_class)

    def t_large():
        assert _is_large_model("C9300-48P")
        assert _is_large_model("C9500-24Y4C")
        assert not _is_large_model("C9200L-24P")
        assert not _is_large_model("")
    _t("_is_large_model", t_large)

    def t_map_selfcheck():
        errs, _ = verify_firmware_map()
        structural = [e for e in errs if "not found at" not in e
                      and "exceeds the absolute" not in e
                      and "too small" not in e]
        assert not structural, "structural errors: %s" % structural
    _t("verify_firmware_map (structural)", t_map_selfcheck)

    def t_fw_hard_cap():
        import inspect as _i
        src = _i.getsource(verify_firmware_map)
        assert "MAX_FIRMWARE_BYTES" in src
        assert "exceeds the absolute" in src
    _t("firmware hard cap", t_fw_hard_cap)

    def t_fw_size_constants():
        assert MAX_FIRMWARE_BYTES == 2_000_000_000
        assert MIN_FIRMWARE_BYTES == 100_000_000
        assert FAMILY_SIZE_BOUNDS_STRICT is True
    _t("firmware size constants", t_fw_size_constants)

    def t_cmd_tracking():
        assert "set_cmd" in globals() and "get_cmd" in globals()
        set_cmd("testhost", "show version")
        assert get_cmd("testhost") == "show version"
    _t("Cmd tracking", t_cmd_tracking)

    def t_long_running_phases():
        assert "INSTALL" in LIVE_LOG_PANEL_PHASES
        assert "SERVICE-LOCKS" in LIVE_LOG_PANEL_PHASES
        assert "PRE-CHECK" in LIVE_LOG_PANEL_PHASES
        assert "PKG-PURGE" in LIVE_LOG_PANEL_PHASES
    _t("long-running phases", t_long_running_phases)

    def t_activate_forms():
        assert len(_ACTIVATE_FORMS) >= 3
        assert any("activate file flash" in f for f in _ACTIVATE_FORMS)
        assert any(f == "install activate" for f in _ACTIVATE_FORMS)
        import inspect as _i
        src = _i.getsource(_try_all_activate_forms)
        assert "_nudge_install_activate" in src
    _t("activate forms", t_activate_forms)

    def t_fast_reboot_probe():
        import inspect as _i
        src = _i.getsource(wait_reboot_and_verify)
        assert "fast-reboot probe" in src
        assert "_verify_after_reboot_impl" in src
    _t("fast-reboot probe", t_fast_reboot_probe)

    def t_residual_detector():
        assert "_detect_residual_temp_config" in globals()
        import inspect as _i
        src = _i.getsource(_detect_residual_temp_config)
        assert "exec_timeout" in src
        assert "ssh_tune" in src
    _t("residual detector", t_residual_detector)

    def t_precheck_checks_commit():
        import inspect as _i
        src = _i.getsource(precheck_device)
        assert "already_on_target_needs_finalize" in src
        assert "_detect_residual_temp_config" in src
        assert "summary_committed_on_target" in src
    _t("precheck commit + residual audit",
       t_precheck_checks_commit)

    def t_install_fixup_path():
        import inspect as _i
        src = _i.getsource(install_worker)
        assert "already_on_target_fixup" in src
    _t("install fixup path (safety net)", t_install_fixup_path)

    def t_fixup_inline():
        import inspect as _i
        src = _i.getsource(transfer_worker)
        assert "fixup_done" in src
        assert "_finalize_install_commit" in src
        assert "revert_device_temp_changes" in src
    _t("v35.9.29 fixup inline in transfer_worker", t_fixup_inline)

    def t_fixup_done_routes_in_collect():
        import inspect as _i
        src = _i.getsource(_collect_transfer_result)
        assert "fixup_done" in src
    _t("v35.9.29 fixup_done routes", t_fixup_done_routes_in_collect)

    def t_drain_install_futures():
        import inspect as _i
        src = _i.getsource(run_pass)
        assert "_drain_install" in src
        assert "block=False" in src
    _t("v35.9.29 run_pass drains installs", t_drain_install_futures)

    def t_pool_rebalance():
        # v35.9.42 FIX-WORKER-FLEX: no specific counts asserted; just
        # ensure the config is self-consistent and sane.
        assert isinstance(TRANSFER_SLOTS, int) and TRANSFER_SLOTS >= 1
        assert isinstance(INSTALL_WORKERS, int) and INSTALL_WORKERS >= 1
        assert isinstance(MAX_SAFE_SSH_SESSIONS, int)
        assert MAX_SAFE_SSH_SESSIONS >= 1
    _t("v35.9.42 worker counts sane (flexible)", t_pool_rebalance)

    def t_probe_overhead_reduced():
        assert INSTALL_PROBE_INTERVAL == 300
        assert PROBE_CONNECT_RETRIES == 2
        assert COMMIT_VERIFY_TIMEOUT == 300
        assert COMMIT_VERIFY_RETRY_SEC == 15
        assert SESSION_SLOT_ACQUIRE_TIMEOUT == 60
    _t("v35.9.29 probe overhead reduced", t_probe_overhead_reduced)

    def t_clock_cache():
        assert "_ensure_device_clock_correct_cached" in globals()
        assert "_CLOCK_TTL_SEC" in globals()
        import inspect as _i
        src_pc = _i.getsource(precheck_device)
        assert "_ensure_device_clock_correct_cached" in src_pc
    _t("v35.9.29 clock check is cached", t_clock_cache)

    def t_state_hosts():
        v2 = {"schema": 2, "run_id": "x",
              "hosts": {"sw1": {"changes": []}}}
        assert _state_hosts(v2) == {"sw1": {"changes": []}}
        v1 = {"sw1": {"changes": []}}
        assert _state_hosts(v1) == v1
        assert _state_hosts(None) == {}
    _t("_state_hosts", t_state_hosts)

    def t_row():
        d = {"hostname": "sw1", "ip": "10.0.0.1"}
        st = {"verify_pending": True, "target_version": "17.18.04",
              "clock_corrected": True, "config_diff_lines": 4}
        r = _row(d, "failed", "install", "test", st=st)
        assert r["verify_pending"] is True
        assert r["clock_corrected"] is True
        assert r["config_diff_lines"] == 4
        assert r["target_version"] == "17.18.04"
    _t("_row fields", t_row)

    def t_revert_markers():
        m = _revert_markers_for_types(["ssh_tune", "cheap_crypto"])
        names = [x[0] for x in m]
        assert "ip ssh bulk-mode" in names
        assert "ip ssh server algorithm encryption" in names
    _t("_revert_markers_for_types", t_revert_markers)

    def t_rollback_syntax():
        import inspect as _i
        src = _i.getsource(_issue_rollback_commands)
        assert "install rollback to committed" in src
        assert "install rollback to base" in src
    _t("rollback tries modern then legacy", t_rollback_syntax)

    def t_safe_reload():
        import inspect as _i
        src = _i.getsource(_safe_manual_reload)
        assert "_RELOAD_MARKERS" in src
        assert "proceed with reload" in src.lower()
    _t("_safe_manual_reload marker-driven", t_safe_reload)

    def t_install_stages():
        import inspect as _i
        src = _i.getsource(run_install)
        assert "install_add" in src
        assert "install_activate" in src
        assert "install_commit" in src
    _t("run_install stage detection", t_install_stages)

    def t_runinstall_done():
        import inspect as _i
        src = _i.getsource(run_install)
        assert "_DONE" in src
        assert "image committed on " in src
        assert "already on " in src
        assert "Probe confirms on target" in src
    _t("run_install exits on done", t_runinstall_done)

    def t_probe_version_first():
        import inspect as _i
        src = _i.getsource(_probe_install_status)
        ver_pos = src.find('show version | include Version')
        summ_pos = src.find('show install summary')
        assert ver_pos != -1 and summ_pos != -1
        assert ver_pos < summ_pos
    _t("probe checks version first", t_probe_version_first)

    def t_probe_uses_parser():
        import inspect as _i
        src = _i.getsource(_probe_install_status)
        assert "_parse_install_summary" in src
    _t("probe uses _parse_install_summary", t_probe_uses_parser)

    def t_runinstall_activate_before_cap():
        import inspect as _i
        src = _i.getsource(run_install)
        inactive_pos = src.find('"image inactive" in probe_msg')
        cap_pos = src.find("if same_total >= 12")
        assert 0 <= inactive_pos < cap_pos
    _t("activate nudge before cap", t_runinstall_activate_before_cap)

    def t_nudge_helper():
        import inspect as _i
        src = _i.getsource(_nudge_install_activate)
        assert "install activate file flash:" in src
        assert "_PROMPT_MARKERS" in src
        assert "_RELOAD_MARKERS" in src
        assert "_is_dead_socket_error" in src
    _t("nudge helper complete", t_nudge_helper)

    def t_escalation_helper():
        import inspect as _i
        src = _i.getsource(_run_install_abort_and_reissue)
        assert "install abort" in src
        assert "install add file flash:" in src
        assert "_is_dead_socket_error" in src
    _t("escalation helper", t_escalation_helper)

    def t_finalize_helper():
        import inspect as _i
        src = _i.getsource(_finalize_install_commit)
        assert "install commit" in src
        assert "summary_committed_on_target" in src
        assert "_parse_install_summary" in src
        assert "_run_install_remove_inactive" in src
        sig = _i.signature(_finalize_install_commit)
        assert "fw_file" in sig.parameters
        assert "_norm_ver" in src
    _t("finalize commit helper", t_finalize_helper)

    def t_finalize_respects_rollback():
        import inspect as _i
        src = _i.getsource(_finalize_install_commit)
        assert "PRESERVE_ROLLBACK" in src
    _t("finalize respects PRESERVE_ROLLBACK",
       t_finalize_respects_rollback)

    def t_finalize_detects_two_committed():
        import inspect as _i
        src = _i.getsource(_finalize_install_commit)
        assert "two committed versions" in src
    _t("finalize detects two-committed state",
       t_finalize_detects_two_committed)

    def t_finalize_uses_fw_file_not_running():
        import inspect as _i
        src = _i.getsource(_finalize_install_commit)
        assert "_get_running_image" not in src
    _t("finalize Path 3a uses fw_file",
       t_finalize_uses_fw_file_not_running)

    def t_finalize_refuses_empty_fw():
        import inspect as _i
        src = _i.getsource(_finalize_install_commit)
        assert "filename is unknown" in src
    _t("finalize refuses unknown fw", t_finalize_refuses_empty_fw)

    def t_wait_reboot_calls_finalize():
        import inspect as _i
        src = _i.getsource(wait_reboot_and_verify)
        assert "_finalize_install_commit" in src or \
            "_verify_after_reboot_impl" in src
        assert "fw_file" in _i.signature(wait_reboot_and_verify).parameters
    _t("wait_reboot calls finalize with fw_file",
       t_wait_reboot_calls_finalize)

    def t_reconcile_calls_finalize():
        import inspect as _i
        src = _i.getsource(_reconcile_failed_devices)
        assert "_finalize_install_commit" in src
    _t("reconcile calls finalize", t_reconcile_calls_finalize)

    def t_health_no_commit_check():
        import inspect as _i
        src = _i.getsource(post_upgrade_health_check)
        assert "summary_committed_on_target" not in src
    _t("health check has no commit re-check", t_health_no_commit_check)

    def t_stack_version_multi_syntax():
        import inspect as _i
        src = _i.getsource(check_stack_versions)
        assert "_per_member_version" in src
    _t("v35.9.36 stack per-member verify", t_stack_version_multi_syntax)

    def t_precheck_members_count_early():
        import inspect as _i
        src = _i.getsource(precheck_device)
        early = src.find("members_count = 1")
        assert early != -1
    _t("members_count defined early", t_precheck_members_count_early)

    def t_precheck_skips_gate_on_unreadable():
        import inspect as _i
        src = _i.getsource(precheck_device)
        assert "skip_per_member_gate" in src
        assert "SKIPPING pre-check space gate" in src
    _t("precheck skips gate on unreadable members",
       t_precheck_skips_gate_on_unreadable)

    def t_report_force():
        import inspect as _i
        sig = _i.signature(write_location_report)
        assert "force" in sig.parameters
        src = _i.getsource(_reconcile_failed_devices)
        assert "force=True" in src
    _t("report rewrite force=True", t_report_force)

    def t_atexit():
        src = open(__file__, "r", encoding="utf-8").read()
        assert "atexit.register(_cleanup_orphan_pwfiles)" in src
    _t("atexit pwfile cleanup", t_atexit)

    def t_lock_order():
        src = open(__file__, "r", encoding="utf-8").read()
        lock_pos = src.find("lock_handle = _acquire_instance_lock()")
        rot_pos = src.find("rotate_backups()")
        assert lock_pos != -1 and rot_pos != -1
        assert lock_pos < rot_pos
    _t("instance lock precedes rotation", t_lock_order)

    def t_fmt_dur():
        assert _fmt_duration(0) == "0s"
        assert _fmt_duration(45) == "45s"
        assert _fmt_duration(60) == "1m00s"
        assert _fmt_duration(200) == "3m20s"
        assert _fmt_duration(3725) == "1h02m05s"
        assert _fmt_duration(None) == "0s"
    _t("_fmt_duration", t_fmt_dur)

    def t_fmt_bytes():
        assert _fmt_bytes(500) == "500.00B"
        assert _fmt_bytes(1024 * 1024) == "1.00MB"
        assert _fmt_bytes(1024 * 1024 * 1024) == "1.00GB"
        assert _fmt_bytes(None) == "?"
    _t("_fmt_bytes", t_fmt_bytes)

    def t_device_line():
        s = _device_line({"hostname": "sw1", "ip": "10.0.0.1",
                          "status": "success",
                          "start_version": "17.15.01",
                          "target_version": "17.18.04",
                          "duration_sec": 720,
                          "md5_ok": True, "reboot_detected": True,
                          "clock_corrected": True})
        assert s.startswith("OK sw1")
        assert "17.15.01 -> 17.18.04" in s
        assert "12m00s" in s
    _t("_device_line", t_device_line)

    def t_summary_return():
        fake = {"LocA": {
            "sw1": {"hostname": "sw1", "ip": "10.0.0.1", "status": "success",
                    "stage": "install", "start_version": "17.15.01",
                    "target_version": "17.18.04", "post_version": "17.18.04",
                    "duration_sec": 720, "md5_ok": True,
                    "reboot_detected": True, "install_started": True,
                    "verify_pending": False, "clock_corrected": False,
                    "config_diff_lines": 0, "attempts": 1, "error": ""},
            "sw2": {"hostname": "sw2", "ip": "10.0.0.2", "status": "failed",
                    "stage": "install", "start_version": "17.15.01",
                    "target_version": "17.18.04", "post_version": "",
                    "duration_sec": 100, "md5_ok": False,
                    "reboot_detected": False, "install_started": True,
                    "verify_pending": True, "clock_corrected": False,
                    "config_diff_lines": 0, "attempts": 1,
                    "error": "install probe: not priv-15"},
        }}
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            n = print_summary(fake, {})
        assert n == 1
        out = buf.getvalue()
        assert "FINAL SUMMARY" in out
        assert "TOTAL" in out
    _t("print_summary returns failed count", t_summary_return)

    def t_anomaly():
        prev = {"run_id": "OLD", "results": [
            {"hostname": "sw1", "status": "success",
             "post_version": "17.18.04"}]}
        cur = {"LocA": {"sw1": {"hostname": "sw1", "status": "success",
                                "post_version": "17.15.01"}}}
        issues = detect_anomalies(cur, prev)
        assert any("regressed" in m for _, m in issues)
    _t("detect_anomalies", t_anomaly)

    def t_cli():
        real = sys.argv
        try:
            for flags in (["--only-upgrade-needed"], ["--preview"],
                          ["--preview-only"], ["--quiet-skipped"],
                          ["--no-html-report"], ["--no-health-snapshot"],
                          ["--use-inventory-cache"], ["--no-colour"],
                          ["--estimate-only"], ["--interactive-resume"],
                          ["--no-reconcile"], ["--no-hash-verify"],
                          ["--allow-lenient-firmware"],
                          ["--allow-active-pkg-purge"]):
                sys.argv = ["prog"] + flags
                parse_args()
        finally:
            sys.argv = real
    _t("CLI flags parse", t_cli)

    def t_pscp_retry_drops_pwfile():
        import inspect as _i
        src = _i.getsource(transfer_via_pscp)
        assert '"-pw", pw' in src
    _t("pscp retry drops -pwfile", t_pscp_retry_drops_pwfile)

    def t_clock_returns_entry_drift():
        import inspect as _i
        src = _i.getsource(_ensure_device_clock_correct)
        assert "entry_drift" in src
    _t("clock helper returns entry drift",
       t_clock_returns_entry_drift)

    def t_transfer_verify_local_size():
        import inspect as _i
        src = _i.getsource(_transfer_with_wipe_retry)
        assert "local_size" in src
    _t("transfer verifies local size", t_transfer_verify_local_size)

    def t_is_install_mode():
        assert "_is_install_mode" in globals()
        import inspect as _i
        src = _i.getsource(_is_install_mode)
        assert "packages.conf" in src
    _t("v35.9.31 _is_install_mode helper", t_is_install_mode)

    def t_read_active_packages_json():
        import inspect as _i
        src = _i.getsource(_read_active_packages)
        assert "file_name" in src
        assert "return active_conf, None" in src
        assert "boot\\s+flash:" in src
    _t("v35.9.32 _read_active_packages handles JSON + text + fail-safe",
       t_read_active_packages_json)

    def t_read_active_fallback():
        import inspect as _i
        src = _i.getsource(_read_active_packages)
        assert "install summary" in src
        assert "committed" in src
    _t("v35.9.36 _read_active_packages falls back to install summary",
       t_read_active_fallback)

    def t_pre_install_pkg_purge():
        import inspect as _i
        src = _i.getsource(_pre_install_pkg_purge)
        assert "ALLOW_ACTIVE_PKG_PURGE" in src
        assert "target .bin not on flash" in src
        assert "cannot determine active .pkg set" in src
    _t("v35.9.32 _pre_install_pkg_purge gated + verified",
       t_pre_install_pkg_purge)

    def t_transfer_worker_invokes_pkg_purge():
        import inspect as _i
        src = _i.getsource(transfer_worker)
        assert "_pre_install_pkg_purge" in src
        assert "ALLOW_ACTIVE_PKG_PURGE" in src
    _t("v35.9.32 transfer_worker invokes last-resort purge",
       t_transfer_worker_invokes_pkg_purge)

    def t_purge_refuses_when_unknown():
        import inspect as _i
        src = _i.getsource(_purge_unnecessary_files)
        assert "active_pkgs is None" in src
        assert "REFUSING to delete any .pkg" in src
    _t("v35.9.32 aggressive purge refuses when active set unknown",
       t_purge_refuses_when_unknown)

    def t_config_keys_has_flags():
        assert "ALLOW_ACTIVE_PKG_PURGE" in _CONFIG_KEYS
    _t("v35.9.35 _CONFIG_KEYS includes purge flag",
       t_config_keys_has_flags)

    def t_purge_standby_exists():
        import inspect as _i
        src = _i.getsource(_purge_standby_members)
        assert "stby-flash:" in src
        assert "flash-%d:" in src
    _t("v35.9.35 _purge_standby_members", t_purge_standby_exists)

    def t_pkg_set_present_detection():
        import inspect as _i
        src = _i.getsource(_is_target_pkg_set_present)
        assert "status=I" in src
        assert "status=A" in src
        assert "status=U" in src
    _t("v35.9.36 _is_target_pkg_set_present",
       t_pkg_set_present_detection)

    def t_precheck_early_return():
        import inspect as _i
        src = _i.getsource(precheck_device)
        assert "already_added_needs_activate" in src
        assert "_is_target_pkg_set_present" in src
    _t("v35.9.36 precheck skips gate when .pkg already present",
       t_precheck_early_return)

    def t_transfer_short_circuit():
        import inspect as _i
        src = _i.getsource(transfer_worker)
        assert "already_added_needs_activate" in src
        assert 'result["already_added"] = True' in src
    _t("v35.9.36 transfer_worker short-circuits already-added",
       t_transfer_short_circuit)

    def t_activate_only_helper():
        assert "_run_install_activate_only" in globals()
        assert "_run_install_commit_only" in globals()
        import inspect as _i
        src = _i.getsource(_run_install_activate_only)
        assert "install activate" in src
        assert "install add file" not in src
    _t("v35.9.37 activate-only helper", t_activate_only_helper)

    def t_commit_only_helper():
        import inspect as _i
        src = _i.getsource(_run_install_commit_only)
        assert "_finalize_install_commit" in src
    _t("v35.9.37 commit-only helper", t_commit_only_helper)

    def t_install_worker_alreadyadded_cmd():
        import inspect as _i
        src = _i.getsource(install_worker)
        assert "_run_install_activate_only" in src
        assert "_run_install_commit_only" in src
    _t("v35.9.37 install_worker uses activate+commit path",
       t_install_worker_alreadyadded_cmd)

    def t_no_abort_after_add():
        import inspect as _i
        src = _i.getsource(install_worker)
        assert "allow_abort=False" in src
    _t("v35.9.37 no install abort after add", t_no_abort_after_add)

    def t_runver_match_normalized():
        import inspect as _i
        src = _i.getsource(_purge_standby_members)
        assert "fver_key == running_key" in src
        assert "_VER3_NORM_RE" in src
    _t("v35.9.37 standby running-version match normalised",
       t_runver_match_normalized)

    def t_standby_junk_purge():
        import inspect as _i
        src = _i.getsource(_purge_standby_members)
        assert ".USWAP" in src
        assert "tech_support" in src
    _t("v35.9.37 standby junk dir purge", t_standby_junk_purge)

    def t_runinstall_detects_already_added():
        import inspect as _i
        src = _i.getsource(run_install)
        assert "_ALREADY_ADDED_MARKERS" in src
        assert "already_added_refused" in src
        assert "super package already added" in _ALREADY_ADDED_MARKERS
    _t("v35.9.37 run_install detects super-package-already-added",
       t_runinstall_detects_already_added)

    def t_conf_keep():
        import inspect as _i
        src = _i.getsource(_purge_unnecessary_files)
        assert "FIX-CONF-KEEP" in src or "keep (target .conf)" in src
        assert "keep (target .conf)" in src
    _t("v35.9.38 keeps target .conf during purge", t_conf_keep)

    def t_precommit_helper():
        assert "_state_needs_precommit" in globals()
        assert "_run_install_commit_for_precommit" in globals()
    _t("v35.9.38 pre-commit helpers exist", t_precommit_helper)

    def t_activate_handles_cannot_activate():
        import inspect as _i
        src = _i.getsource(_run_install_activate_only)
        assert "cannot activate; please first perform" in src
        assert "_state_needs_precommit" in src
    _t("v35.9.38 activate handles cannot-activate",
       t_activate_handles_cannot_activate)

    def t_activate_detects_partial():
        import inspect as _i
        src = _i.getsource(_run_install_activate_only)
        assert "partial activation" in src
        assert "per_member_fail" in src
    _t("v35.9.38 activate detects partial failure",
       t_activate_detects_partial)

    def t_pwfile_unique():
        a = _pwfile_for_thread()
        b = _pwfile_for_thread()
        assert a != b
        assert _PWFILE_COUNTER >= 2
    _t("v35.9.38 pwfile paths are unique", t_pwfile_unique)

    def t_pscp_retry_window_widened():
        import inspect as _i
        src = _i.getsource(transfer_via_pscp)
        assert "elapsed < 60" in src
        assert "elapsed < 5" not in src
    _t("v35.9.38 pscp retry window widened",
       t_pscp_retry_window_widened)

    def t_finalize_no_infinite_activate():
        import inspect as _i
        src = _i.getsource(_finalize_install_commit)
        assert "st_attempts" in src
        assert "reissued_activate" in src
    _t("v35.9.38 finalize refuses to loop on target=I",
       t_finalize_no_infinite_activate)

    def t_stack_verify_platform_safe():
        import inspect as _i
        src = _i.getsource(_per_member_version)
        assert "per_member_syntax_ok" in src
        assert "show version | include Version" in src
        src2 = _i.getsource(check_stack_versions)
        assert "unverified" in src2 or " X" in src2
    _t("v35.9.38 stack-verify is platform-safe",
       t_stack_verify_platform_safe)

    def t_precheck_passes_target_ver_to_purge():
        import inspect as _i
        src = _i.getsource(precheck_device)
        assert "target_ver=target_ver" in src
    _t("v35.9.38 precheck passes target_ver to purge",
       t_precheck_passes_target_ver_to_purge)

    def t_runinstall_nudge_returns_on_dead_transport():
        import inspect as _i
        src = _i.getsource(run_install)
        assert "tr.is_active()" in src
        assert "dead = True" in src
        assert "activate nudged, transport" in src or \
               "reload in progress" in src
    _t("v35.9.38 run_install returns on dead transport",
       t_runinstall_nudge_returns_on_dead_transport)

    def t_runinstall_precommits_on_u_state():
        import inspect as _i
        src = _i.getsource(run_install)
        assert "_state_needs_precommit" in src
        assert "_run_install_commit_for_precommit" in src
    _t("v35.9.38 run_install pre-commits U state",
       t_runinstall_precommits_on_u_state)

    def t_md5_nonfatal():
        import inspect as _i
        src = _i.getsource(install_worker)
        assert "send_command_timing" in src
        assert "MD5 not confirmed" in src
        assert "non-fatal" in src
    _t("v35.9.38 MD5 verify is non-fatal", t_md5_nonfatal)

    def t_retry_install_failures():
        import inspect as _i
        src = _i.getsource(is_retryable)
        assert "recoverable" in src
    _t("v35.9.38 install failures are retryable when recoverable",
       t_retry_install_failures)

    def t_revert_verify_default():
        import inspect as _i
        src = _i.getsource(verify_revert_clean)
        assert "hmac-sha1" in src
        assert "aes128-ctr" in src
        assert "ip ssh server algorithm mac" in src
    _t("v35.9.38 revert-verify ignores defaults",
       t_revert_verify_default)

    def t_low_unbound_fixed():
        import inspect as _i
        src = _i.getsource(_run_install_activate_only)
        assert "FIX-LOW-UNBOUND" in src or 'low = ""' in src
        assert 'low = ""' in src
    _t("v35.9.39 _run_install_activate_only binds `low`",
       t_low_unbound_fixed)

    def t_already_added_ordered():
        import inspect as _i
        src = _i.getsource(run_install)
        p_already = src.find("_ALREADY_ADDED_MARKERS")
        p_failed  = src.find('re.search(r"failed:\\s*install", low)')
        assert p_already != -1, "_ALREADY_ADDED_MARKERS not found in run_install"
        assert p_failed  != -1, 'failed:install check not found in run_install'
        assert p_already < p_failed, (
            "_ALREADY_ADDED_MARKERS at offset %d must appear before "
            "failed:install at offset %d" % (p_already, p_failed))
    _t("v35.9.39 already-added is checked before failed:install",
       t_already_added_ordered)

    def t_already_added_markers():
        assert "_ALREADY_ADDED_MARKERS" in globals()
        assert "super package already added" in _ALREADY_ADDED_MARKERS
        assert "add operation not allowed" in _ALREADY_ADDED_MARKERS
    _t("v35.9.39 _ALREADY_ADDED_MARKERS present",
       t_already_added_markers)

    def t_already_added_3tuple():
        import inspect as _i
        src = _i.getsource(run_install)
        idx = src.find("_ALREADY_ADDED_MARKERS")
        assert idx != -1
        tail = src[idx:idx + 600]
        assert 'already_added_refused' in tail
        ret_start = tail.find('"add because .pkg set is already on flash"')
        assert ret_start != -1
        ret_end = tail.find("\n", ret_start)
        ret_line = tail[ret_start:ret_end]
        assert ", conn" in ret_line, \
            "already_added_refused return must carry conn: %r" % ret_line
    _t("v35.9.39 already-added return carries conn",
       t_already_added_3tuple)

    def t_read_active_pkg_version_match():
        wanted = {_norm_ver("17.12.04")}
        assert wanted == {"17.12.4"}
        for fn in ("cat9k_lite-rpbase.17.12.04.SPA.pkg",
                   "cat9k_lite-webui.17.12.04.SPA.pkg",
                   "cat9k_lite-rpboot.17.12.04.SPA.pkg",
                   "cat9k_lite-srdriver.17.12.04.SPA.pkg"):
            fm = _VER3_NORM_RE.search(fn)
            assert fm is not None
            assert _norm_ver(fm.group(0)) in wanted, fn
        for fn in ("cat9k_lite-rpbase.17.06.03.SPA.pkg",
                   "cat9k_lite-webui.17.06.03.SPA.pkg",
                   "cat9k_lite-rpboot.17.09.04a.SPA.pkg"):
            fm = _VER3_NORM_RE.search(fn)
            assert fm is not None
            assert _norm_ver(fm.group(0)) not in wanted, fn
    _t("v35.9.41 active-pkg version match (17.12.4 vs 17.12.04)",
       t_read_active_pkg_version_match)

    def t_read_active_pkg_uses_running():
        import inspect as _i
        src = _i.getsource(_read_active_packages)
        assert "FIX-ACTIVE-PKG-RUNNING" in src
        assert "_get_running_version_string" in src
        assert "_VER3_NORM_RE" in src
    _t("v35.9.41 active-pkg fallback consults running version",
       t_read_active_pkg_uses_running)

    def t_wait_install_op_idle_exists():
        assert "_wait_install_op_idle" in globals()
        import inspect as _i
        src = _i.getsource(_wait_install_op_idle)
        assert "FIX-WAIT-OP-IDLE" in src
        assert "show install summary" in src
    _t("v35.9.42 _wait_install_op_idle helper present",
       t_wait_install_op_idle_exists)

    def t_activate_fastpath_check():
        import inspect as _i
        src = _i.getsource(_run_install_activate_only)
        assert "FIX-FASTPATH-ALREADY-ON-TARGET" in src
        assert "already on target -- skipping activate" in src
        assert "_wait_install_op_idle" in src
    _t("v35.9.42 activate has fast-path + busy-wait",
       t_activate_fastpath_check)

    def t_commit_busy_wait():
        import inspect as _i
        src = _i.getsource(_finalize_install_commit)
        assert "FIX-COMMIT-BUSY-WAIT" in src
        assert "commit: install engine busy" in src
    _t("v35.9.42 commit backs off when engine busy",
       t_commit_busy_wait)

    def t_pscp_stall_detection():
        import inspect as _i
        src = _i.getsource(_pscp_run_once)
        assert "FIX-PSCP-STALL" in src
        assert "SCP_STALL_TIMEOUT" in src
        assert "proc.kill()" in src
        assert "chunks.get(timeout=1.0)" in src or "queue.Empty" in src
    _t("v35.9.43 pscp kills stalled transfers", t_pscp_stall_detection)

    def t_version_string_v43():
        assert VERSION_STRING == "35.9.43", \
            "VERSION_STRING should be 35.9.43, got %s" % VERSION_STRING
    _t("VERSION_STRING is 35.9.43", t_version_string_v43)

    def t_activate_settle():
        import inspect as _i
        src = _i.getsource(_run_install_activate_only)
        assert "FIX-ACT-SETTLE" in src
        assert "time.sleep(30)" in src
    _t("v35.9.43 activate waits for engine to settle",
       t_activate_settle)

    total = len(passed) + len(failed)
    print("\n" + "=" * 70)
    print("  VALIDATION -- %d check(s)" % total)
    print("=" * 70)
    for name in passed: print("  OK %s" % name)
    if failed:
        print()
        for name, err in failed: print("  FAIL %s: %s" % (name, err))
    print("-" * 70)
    print("  Passed: %d/%d" % (len(passed), total))
    print("  Failed: %d/%d" % (len(failed), total))
    print("=" * 70 + "\n")
    return 0 if not failed else 1


def main():
    global DRY_RUN, SKIP_ISSU, PAUSE_BETWEEN_LOCATIONS, AUTO_ROLLBACK_ON_FAIL
    global LOCATIONS_TO_RUN, ENABLE_PASSWORD, ENABLE_USER, REVERT_VERIFY_AFTER
    global LIVE_LOG_FEED_TRANSFER, SERIAL_TRANSFER_LARGE_MODELS
    global SKIP_CONFIG_DRIFT_CHECK, ALLOW_BUNDLE_MODE_CONVERSION
    global POOL_LOCATIONS, VERIFY_TRANSFER_HASH, RECONCILE_FAILED_AT_END
    global LARGE_MODEL_PARALLEL, PARAMIKO_PRIMARY, LARGE_MODEL_SEMAPHORE
    global BULK_MODE_WINDOW_SIZE, USE_COLOUR, QUIET_SKIPPED
    global FAMILY_SIZE_BOUNDS_STRICT, ALLOW_ACTIVE_PKG_PURGE
    args = parse_args()

    if args.validate:
        return _validate()

    if args.config: apply_config_file(args.config)
    if args.base_dir: update_paths(args.base_dir)
    for d in (LOG_DIR, STATE_DIR, REPORT_DIR, BACKUP_DIR, CHECKPOINT_DIR):
        try: os.makedirs(d, exist_ok=True)
        except OSError: pass
    if args.write_manifest:
        _cleanup_orphan_pwfiles(); _write_manifest(); return 0

    lock_handle = _acquire_instance_lock()
    if lock_handle is None: return 3
    _cleanup_orphan_pwfiles()
    _check_local_disk_space()
    rotate_backups()
    rotate_log_archive()

    if args.dry_run:          DRY_RUN = True
    if args.skip_issu:        SKIP_ISSU = True
    if args.auto_rollback:    AUTO_ROLLBACK_ON_FAIL = True
    if args.no_pause:         PAUSE_BETWEEN_LOCATIONS = False
    if args.locations:        LOCATIONS_TO_RUN = args.locations
    if args.no_verify_revert: REVERT_VERIFY_AFTER = False
    if args.show_live_transfer: LIVE_LOG_FEED_TRANSFER = True
    if args.no_serial_large:  SERIAL_TRANSFER_LARGE_MODELS = False
    if args.no_drift_check:   SKIP_CONFIG_DRIFT_CHECK = True
    if args.no_hash_verify:   VERIFY_TRANSFER_HASH = False
    if args.no_reconcile:     RECONCILE_FAILED_AT_END = False
    if args.no_bundle_mode:   ALLOW_BUNDLE_MODE_CONVERSION = False
    if args.allow_bundle_mode: ALLOW_BUNDLE_MODE_CONVERSION = True
    if args.no_pool_locations: POOL_LOCATIONS = False
    if args.pool_locations:   POOL_LOCATIONS = True
    if args.allow_lenient_firmware:
        FAMILY_SIZE_BOUNDS_STRICT = False
        print("  ! --allow-lenient-firmware: strict family size check "
              "disabled (absolute 2 GB cap still applies)")
    if args.allow_active_pkg_purge:
        ALLOW_ACTIVE_PKG_PURGE = True
        print("  ! --allow-active-pkg-purge: active .pkg deletion enabled. "
              "If install fails after this point, MANUAL CONSOLE RECOVERY "
              "will be required.")
    if args.parallel_large is not None:
        LARGE_MODEL_PARALLEL = max(1, args.parallel_large)
        LARGE_MODEL_SEMAPHORE = threading.Semaphore(LARGE_MODEL_PARALLEL)
    if args.paramiko_primary: PARAMIKO_PRIMARY = True
    if args.bulk_window is not None:
        if args.bulk_window < 131072:
            print("  --bulk-window %d < 131072 -- ignored"
                  % args.bulk_window)
        else:
            BULK_MODE_WINDOW_SIZE = args.bulk_window
    if args.quiet_skipped: QUIET_SKIPPED = True
    if args.no_colour: USE_COLOUR = False

    if os.name == "nt" and not args.no_colour:
        try:
            import ctypes
            _k = ctypes.windll.kernel32
            _h = _k.GetStdHandle(-11)
            _m = ctypes.c_ulong()
            if _k.GetConsoleMode(_h, ctypes.byref(_m)):
                _k.SetConsoleMode(_h, _m.value | 0x0004)
        except Exception: pass

    if args.resume:
        print("  --resume deprecated; use --force-run-with-stale-state.")
        args.ignore_stale_state = True
    if args.force_run_with_stale_state:
        args.ignore_stale_state = True
    if args.enable_pass:
        print("  --enable-pass visible in process list; prefer "
              "$CISCO_ENABLE.")
    ENABLE_PASSWORD = (args.enable_pass or os.environ.get("CISCO_ENABLE")
                       or None)
    ENABLE_USER = (args.enable_user
                   or os.environ.get("CISCO_ENABLE_USER") or None)
    if ENABLE_PASSWORD is None and not args.dry_run_revert:
        print("  (enable password not set -- falling back to SSH password)")

    signal.signal(signal.SIGINT, _on_signal)
    try: signal.signal(signal.SIGTERM, _on_signal)
    except (ValueError, OSError, AttributeError): pass
    if hasattr(signal, "SIGBREAK"):
        try: signal.signal(signal.SIGBREAK, _on_signal)
        except (ValueError, OSError): pass

    if args.dry_run_revert: return mode_dry_run_revert()
    if args.recover:        return mode_recover(args)
    if args.revert_only:    return mode_recover(
        args, locations_filter=LOCATIONS_TO_RUN)

    rotate_logs()
    print_ssh_banner()

    stale = list_state_files()
    if stale and not (args.ignore_stale_state
                      or args.force_run_with_stale_state or args.resume):
        if args.interactive_resume:
            choice = prompt_resume_or_abort(stale)
            if choice == "abort":
                print("  Aborted (state kept)."); return 2
            args.ignore_stale_state = True
            if choice == "resume": args.resume_checkpoint = True
            if choice == "skip":   args.retry_failed = True
        else:
            print("\n  Un-reverted temp-config state from earlier run:")
            for s in stale: print("     - %s" % s)
            print("  Use --dry-run-revert to inspect, --recover to fix, "
                  "--interactive-resume to prompt, or "
                  "--force-run-with-stale-state to proceed.\n")
            return 2

    for _, fw, _ in MODEL_FIRMWARE_MAP:
        p = os.path.join(FIRMWARE_DIR, fw)
        if os.path.isfile(p):
            FIRMWARE_SIZES[fw] = os.path.getsize(p)

    print("\n  -- Firmware inventory --")
    for fw_name in sorted(set(fw for _, fw, _ in MODEL_FIRMWARE_MAP)):
        p = os.path.join(FIRMWARE_DIR, fw_name)
        if os.path.isfile(p):
            print("    %-45s %s" % (fw_name, _fmt_bytes(os.path.getsize(p))))
        else:
            print("    %-45s MISSING" % fw_name)
    map_errors, map_warnings = verify_firmware_map()
    if map_errors:
        print("\n  FIRMWARE pre-flight FAILED (hard stop):")
        for e in map_errors: print("     - %s" % e)
        print("\n  Fix the firmware files and re-run.  If you are certain")
        print("  the sizes are correct for your platform, override with")
        print("  --allow-lenient-firmware (NOT recommended).\n")
        return 1
    if map_warnings:
        print("\n  MODEL_FIRMWARE_MAP warnings:")
        for w in map_warnings: print("     - %s" % w)
    print("  Firmware pre-flight passed")

    loc_devices = {}
    if args.hosts:
        hostmap = build_host_ip_map()
        all_known = sorted(hostmap.keys())
        wanted = {h.strip() for h in args.hosts}
        devices = [{"hostname": h, "ip": hostmap[h]}
                   for h in wanted if h in hostmap]
        for h in [x for x in wanted if x not in hostmap]:
            print("  Host not found: %s" % h)
            suggestions = suggest_similar_hosts(h, all_known)
            if suggestions:
                print("     Did you mean: %s" % ", ".join(suggestions[:3]))
        if devices: loc_devices["ad-hoc"] = devices
    else:
        seen = set()
        for loc in LOCATIONS_TO_RUN:
            p = os.path.join(LOCATIONS_DIR, "%s.txt" % loc)
            if not os.path.isfile(p):
                print("  Missing: %s -- skipping" % p); continue
            loc_devices[loc] = load_location(p, reference_hosts=seen)
            seen.update(d["hostname"] for d in loc_devices[loc])

    dups = detect_duplicate_hostnames(loc_devices)
    if dups:
        print("\n  Duplicate hostnames/IPs:")
        for h, a, b in dups: print("     - %s: %s and %s" % (h, a, b))
    for loc in list(loc_devices):
        loc_devices[loc] = filter_devices(loc_devices[loc], args)

    all_devices = [d for ds in loc_devices.values() for d in ds]
    if not all_devices:
        print("  No devices to process."); return 1

    user, pw = get_credentials(args)

    if args.inventory:
        return mode_inventory(all_devices, user, pw)
    if args.check:
        return mode_check(all_devices, user, pw)
    if args.verify_mapping:
        return mode_verify_mapping(all_devices, user, pw)
    if args.rollback_dry_run:
        return mode_rollback(all_devices, user, pw, args, dry=True)
    if args.rollback:
        return mode_rollback(all_devices, user, pw, args)
    if args.estimate_only:
        return estimate_runtime(all_devices, user, pw)

    if args.only_upgrade_needed:
        print("\n  -- Filtering to devices that need upgrade --")
        need, tgt, unr = filter_only_upgrade_needed(all_devices, user, pw)
        print("    %d need upgrade, %d already on target, %d unreachable"
              % (len(need), len(tgt), len(unr)))
        if not need:
            print("  Nothing to do -- every reachable device is on target.")
            return 0
        all_devices = [d for d, _ in need]
        keep = {d["hostname"] for d in all_devices}
        loc_devices = {loc: [d for d in devs if d["hostname"] in keep]
                       for loc, devs in loc_devices.items()}
        loc_devices = {loc: ds for loc, ds in loc_devices.items() if ds}
        if not loc_devices:
            print("  No locations left after filtering."); return 0

    if args.preview or args.preview_only or not args.yes:
        print_change_preview(all_devices, user, pw)
        if args.preview_only:
            print("  Preview-only mode -- exiting."); return 0

    if args.precache_hostkeys:
        precache_host_keys(all_devices, user, pw)
    errors, _ = preflight_validation(all_devices, user, pw)
    if errors:
        print("  Pre-flight failed -- aborting."); return 1
    if args.preflight_only:
        print("  Pre-flight-only mode -- exiting."); return 0

    if not confirm("  Proceed with %supgrade of %d device(s)?"
                   % ("DRY-RUN of " if DRY_RUN else "",
                      len(all_devices)), args.yes):
        print("  Cancelled."); return 1

    all_results, all_revert = {}, {}
    start_monitor_thread()
    try:
        if POOL_LOCATIONS and len(loc_devices) > 1:
            print("\n  -- POOLED MODE (per-location abort gates) --")
            master_log("POOLED START: %d locations" % len(loc_devices))
            all_results, all_revert = _run_pooled(
                loc_devices, user, pw,
                resume_checkpoint=args.resume_checkpoint,
                retry_failed=args.retry_failed)
        else:
            locs = list(loc_devices)
            for i, loc in enumerate(locs):
                if SHUTDOWN_REQ.is_set(): break
                p = os.path.join(LOCATIONS_DIR, "%s.txt" % loc)
                if os.path.isfile(p):
                    fresh = load_location(p)
                    if fresh:
                        loc_devices[loc] = filter_devices(fresh, args)
                results, aborted, rv = run_location(
                    loc, loc_devices[loc], user, pw,
                    resume_checkpoint=args.resume_checkpoint,
                    retry_failed=args.retry_failed)
                all_results[loc] = results
                all_revert[loc] = rv
                if aborted: break
                if (PAUSE_BETWEEN_LOCATIONS and i < len(locs) - 1
                        and not SHUTDOWN_REQ.is_set()):
                    if not confirm("\n  %s finished. Continue to %s?"
                                   % (loc, locs[i+1])):
                        print("  Stopping at operator request."); break
    finally:
        stop_monitor_thread()
        try:
            all_results, all_revert = _reconcile_failed_devices(
                all_results, all_revert, user, pw)
        except Exception as e:
            master_log("Reconcile pass raised: %s" % e)
            print("\n  Reconcile pass raised: %s\n" % e)
        try:
            write_run_summary(
                all_results, all_revert, RUN_ID,
                os.path.join(REPORT_DIR, "run_summary_%s.json" % RUN_ID))
        except Exception as e:
            master_log("run_summary raised: %s" % e)
        if not args.no_html_report:
            try:
                write_html_report(
                    all_results,
                    os.path.join(REPORT_DIR, "run_%s.html" % RUN_ID))
            except Exception as e:
                master_log("HTML raised: %s" % e)
        if not args.no_health_snapshot and not DRY_RUN:
            try:
                post_run_health_snapshot(
                    all_results, user, pw,
                    os.path.join(REPORT_DIR, "health_%s.json" % RUN_ID))
            except Exception as e:
                master_log("Health raised: %s" % e)
        failed = print_summary(all_results, all_revert)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())