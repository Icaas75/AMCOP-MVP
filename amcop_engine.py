import socket
import time
import datetime
import paramiko
import docker

import config

COMMAND_TIMEOUT_S = 10  # payload execution deadline inside the lab target

# ==========================================
# 1. REAL RED AI AGENT
# ==========================================

# MITRE ATT&CK technique registry: simulated discovery payloads (authorized
# lab only). All payloads are read-only recon against the disposable target.
TECHNIQUES = {
    "T1087": {"name": "Account Discovery", "payload": "cat /etc/passwd"},
    "T1049": {"name": "Network Connections Discovery", "payload": "netstat -an || ss -tulpn"},
    "T1082": {"name": "System Information Discovery", "payload": "uname -a"},
    "T1016": {"name": "System Network Configuration Discovery", "payload": "ip addr || ifconfig -a"},
}
DEFAULT_PAYLOAD = "uname -a"


def get_payload_for_technique(mitre_technique):
    entry = TECHNIQUES.get(mitre_technique)
    return entry["payload"] if entry else DEFAULT_PAYLOAD


def get_technique_name(mitre_technique):
    entry = TECHNIQUES.get(mitre_technique)
    return entry["name"] if entry else "Unknown / custom technique"


def run_red_agent(target_ip, target_port, username, password, mitre_technique):
    """Execute the simulated discovery payload over SSH.

    Returns (status, console_display, ssh_client). The caller OWNS the returned
    ssh_client and must close it (or pass None on failure) -- the orchestration
    cycle deliberately keeps the session open while Blue AI snapshots the
    process tree, so the attacker's sshd session is observable telemetry.
    """
    print(f"\n[RED AI] Targeted node: {target_ip}:{target_port}")

    command = get_payload_for_technique(mitre_technique)

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(target_ip, port=int(target_port), username=username,
                    password=password, timeout=5)

        print(f"[RED AI] Executing live instruction: '{command}'")
        # Explicit command timeout: a hung payload must not stall the cycle.
        stdin, stdout, stderr = ssh.exec_command(command, timeout=COMMAND_TIMEOUT_S)

        try:
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
        except socket.timeout:
            ssh.close()
            return ("COMMAND_TIMEOUT",
                    f"Command '{command}' exceeded {COMMAND_TIMEOUT_S}s and was aborted.",
                    None)

        if error and not output:
            ssh.close()
            return "FAILED", f"SSH Execution Error:\n{error}", None

        console_display = f"root@{config.TARGET_CONTAINER}:~# {command}\n{output}"
        # Session intentionally left open for the Blue AI observation window.
        return "SUCCESS", console_display, ssh

    except Exception as e:
        error_msg = (f"CRITICAL CONNECTIVITY FAILURE: Could not connect to "
                     f"{target_ip}:{target_port} via SSH.\nReason: {e}")
        print(f"[RED AI] {error_msg}")
        return "CONNECTION_ERROR", error_msg, None


# ==========================================
# 2. ADVANCED BLUE AI AGENT (BEHAVIORAL TELEMETRY)
# ==========================================

ANOMALY_THRESHOLD = 40  # score >= threshold => DETECTED


def analyze_process_tree(raw_telemetry):
    """Pure behavioral analysis of a Linux `ps aux` snapshot.

    Returns (status, anomaly_score, risk_indicators, processes_audited).
    Deterministic and side-effect free so it can be unit tested with fixture
    process trees.
    """
    lines = raw_telemetry.splitlines()
    anomaly_score = 0
    risk_indicators = []

    for line in lines[1:]:  # Skip the header row
        parts = line.split()
        if len(parts) < 11:
            continue

        user = parts[0]       # The user executing the binary
        pid = parts[1]        # Process ID
        command = " ".join(parts[10:])  # Full execution string

        # Behavioral Rule A: Administrative Shell Reconnaissance Tracking.
        # Covers all four implemented techniques: T1087 (cat /etc), T1049
        # (netstat/ss), T1082 (uname), T1016 (ip addr/ifconfig).
        recon_signatures = ["cat /etc", "netstat", "ss -", "uname", "ip addr", "ifconfig"]
        if user == "root" and any(cmd in command for cmd in recon_signatures):
            anomaly_score += 40
            risk_indicators.append(f"High-risk administrative discovery: PID {pid} ({command})")

        # Behavioral Rule B: Evasion Tracking (backgrounded/silent execution)
        if "sleep" in command or "nohup" in command:
            anomaly_score += 30
            risk_indicators.append(f"Potential execution persistence/evasion: PID {pid}")

        # Behavioral Rule C: Non-interactive (no TTY) remote shell sessions.
        # A live `sshd: <user>@notty` process is a direct IoC of an active
        # remote-access session (the adversary's channel), so it carries the
        # same 40-point weight as confirmed admin reconnaissance. This makes
        # detection genuine and repeatable while Red's session is held open.
        if "sshd" in command and "notty" in command:
            anomaly_score += 40
            risk_indicators.append(f"Rogue non-interactive shell socket verified: PID {pid}")

    anomaly_score = min(anomaly_score, 100)  # cap display range
    status = "DETECTED" if anomaly_score >= ANOMALY_THRESHOLD else "MISSED"
    return status, anomaly_score, risk_indicators, len(lines) - 1


def run_blue_agent(target_ip, attack_timestamp):
    print(f"\n[BLUE AI] Analyzing security events for target: {target_ip}")

    try:
        client = docker.from_env()
        container = client.containers.get(config.TARGET_CONTAINER)

        # Gather real-time runtime process states from the live container
        exec_result = container.exec_run("ps aux")
        raw_telemetry = exec_result.output.decode("utf-8", errors="replace").strip()

        status, anomaly_score, risk_indicators, audited = analyze_process_tree(raw_telemetry)

        # Structured evidence for evaluation integrity: the decision is made
        # purely from the observed process tree, never from Red's self-report.
        evidence = {
            "anomaly_score": anomaly_score,
            "threshold": ANOMALY_THRESHOLD,
            "risk_indicators": risk_indicators,
            "processes_audited": audited,
            "telemetry_source": "docker-exec ps aux",
        }

        # Format an analyst telemetry report for the dashboard console view
        formatted_analysis = (
            f"=== BLUE AI RUNTIME SECURITY ANALYSIS ===\n"
            f"Target Namespace   : {config.TARGET_CONTAINER}\n"
            f"Telemetry Source   : Linux Kernel Process Tree via Docker Socket\n"
            f"Processes Audited  : {audited}\n"
            f"Calculated Threat Anomaly Score: {anomaly_score}/100\n"
            f"--------------------------------------------------\n"
            f"Active Behavioral Alerts:\n"
        )

        if risk_indicators:
            for indicator in risk_indicators:
                formatted_analysis += f"[RISK ALERT] {indicator}\n"
        else:
            formatted_analysis += "[OK] System baseline normal. No anomalies identified.\n"

        formatted_analysis += f"\n=== RAW TELEMETRY SNAPSHOT ===\n{raw_telemetry}"

        return status, formatted_analysis, evidence

    except Exception as e:
        error_msg = (f"DOCKER CONTAINER TELEMETRY ERROR: Is "
                     f"'{config.TARGET_CONTAINER}' running?\nDetails: {e}")
        print(f"[BLUE AI] {error_msg}")
        return "TELEMETRY_ERROR", error_msg, None


# ==========================================
# 3. WHITE AI ORCHESTRATOR
# ==========================================

def evaluate_resilience(red_status, blue_status):
    """Pure verdict rule: the lab is RESILIENT only when the attack succeeded
    AND the defense detected it. Any infrastructure error is not 'resilient'."""
    if red_status == "SUCCESS" and blue_status == "DETECTED":
        return "RESILIENT"
    return "VULNERABLE"


def classify_detection(red_status, blue_status):
    """Confusion-matrix class using execution ground truth.

    Ground truth = did the attack actually execute (red SUCCESS)?
      TP: attack executed AND detected        FN: attack executed AND missed
      FP: attack did NOT execute but flagged  TN: no attack AND not flagged
    Execution failures (FAILED/CONNECTION_ERROR/COMMAND_TIMEOUT) and telemetry
    errors are tracked separately -- they are neither detection successes nor
    detection failures.
    """
    if blue_status == "TELEMETRY_ERROR":
        return "UNSCORED_TELEMETRY_ERROR"
    if red_status == "SUCCESS":
        return "TP" if blue_status == "DETECTED" else "FN"
    # Red did not execute the payload (connection/command failure or timeout)
    if red_status in ("FAILED", "CONNECTION_ERROR", "COMMAND_TIMEOUT"):
        if blue_status == "DETECTED":
            return "FP_SUSPECTED"
        return "TN"
    return "UNSCORED"


def detection_rationale(red_status, blue_status, evidence):
    """Human-readable justification stored with every assessment."""
    if blue_status == "TELEMETRY_ERROR":
        return "No detection decision: telemetry collection failed (unscored)."
    if evidence is None:
        return "No detection decision: evidence unavailable (unscored)."
    indicators = evidence.get("risk_indicators", [])
    score = evidence.get("anomaly_score", 0)
    threshold = evidence.get("threshold", ANOMALY_THRESHOLD)
    if blue_status == "DETECTED":
        reasons = "; ".join(indicators) if indicators else "evidence present"
        return (f"Score {score}/{threshold} threshold met from observed evidence: "
                f"{reasons}")
    return (f"Score {score} below {threshold} threshold; no behavioral rule "
            f"matched the observed process tree.")


def log_cycle_to_database(report_data):
    try:
        client = config.get_mongo_client()
        db = client[config.MONGO_DB]
        db[config.MONGO_COLLECTION].insert_one(report_data)
        print("[WHITE AI DB] Operational metrics logged to MongoDB successfully.")
        return True
    except Exception as e:
        print(f"[WHITE AI DB] Failed to save telemetry to Database: {e}")
        return False


def run_orchestration_cycle(target_ip, target_port, user, pwd, technique):
    cycle_start = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("=" * 50)
    print(f"[WHITE AI] Initializing Live Cycle at {cycle_start}")
    print("=" * 50)

    red_ssh = None
    red_started = None
    try:
        # Red AI strikes first; session is kept open on purpose.
        red_started = time.monotonic()
        red_status, red_output, red_ssh = run_red_agent(
            target_ip, target_port, user, pwd, technique)

        # Observation window: let process state propagate while the attacker's
        # SSH session is still alive so Blue AI reliably observes it.
        time.sleep(1)

        blue_status, blue_output, blue_evidence = run_blue_agent(target_ip, cycle_start)
    finally:
        # Always tear down the attacker session, even if Blue AI errored.
        if red_ssh is not None:
            try:
                red_ssh.close()
            except Exception:
                pass

    # Detection latency: Red payload launch -> Blue decision complete. For a
    # SUCCESS cycle this includes the fixed 1s observation window; it measures
    # the platform's detection pipeline delay, not attacker dwell time.
    detection_latency_ms = (
        int((time.monotonic() - red_started) * 1000) if red_started is not None else None)

    report_payload = {
        "timestamp": cycle_start,
        "target_host": target_ip,
        "target_port": target_port,
        "mitre_technique": technique,
        "technique_name": get_technique_name(technique),
        "red_outcome": red_status,
        "blue_outcome": blue_status,
        "red_raw_console": red_output,
        "blue_raw_console": blue_output,
        "system_resilience": evaluate_resilience(red_status, blue_status),
        "detection_evidence": blue_evidence,
        "detection_rationale": detection_rationale(red_status, blue_status, blue_evidence),
        "detection_latency_ms": detection_latency_ms,
        "confusion_class": classify_detection(red_status, blue_status),
    }

    log_cycle_to_database(report_payload)
    return report_payload


def trigger_manual_simulation(technique_id):
    return run_orchestration_cycle(
        config.TARGET_HOST,
        config.TARGET_PORT,
        config.TARGET_USER,
        config.TARGET_PASSWORD,
        technique_id,
    )


if __name__ == "__main__":
    trigger_manual_simulation("T1087")
