import os
import time
import datetime
import paramiko
import docker
from pymongo import MongoClient

# ==========================================
# 1. REAL RED AI AGENT
# ==========================================
def run_red_agent(target_ip, target_port, username, password, mitre_technique):
    print(f"\n[🔴 RED AI] Targeted node: {target_ip}:{target_port}")
    
    # FIX: We execute the commands directly (removing nohup and output silencing)
    # so that the real terminal output is actually captured and sent back to the UI.
    if mitre_technique == "T1087":
        command = "cat /etc/passwd"  # Account Discovery
    elif mitre_technique == "T1049":
        command = "netstat -an || ss -tulpn"  # Network Connections Discovery
    else:
        command = "uname -a"
        
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(target_ip, port=target_port, username=username, password=password, timeout=5)
        
        print(f"[🔴 RED AI] Executing live instruction: '{command}'")
        stdin, stdout, stderr = ssh.exec_command(command)
        
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        ssh.close()
        
        if error and not output:
            return "FAILED", f"SSH Execution Error:\n{error}"
            
        console_display = f"root@target-node-01:~# {command}\n{output}"
        return "SUCCESS", console_display
        
    except Exception as e:
        # Fallback to clear, readable infrastructure logging if your target container is offline
        error_msg = f"CRITICAL CONNECTIVITY FAILURE: Could not connect to {target_ip}:{target_port} via SSH.\nReason: {e}"
        print(f"[🔴 RED AI] {error_msg}")
        return "CONNECTION_ERROR", error_msg

# ==========================================
# 2. ADVANCED BLUE AI AGENT (BEHAVIORAL TELEMETRY)
# ==========================================

def run_blue_agent(target_ip, attack_timestamp):
    print(f"\n[🔵 BLUE AI] Analyzing security events for target: {target_ip}")
    
    try:
        client = docker.from_env()
        container = client.containers.get("target-node-01")
        
        # 1. Gather real-time runtime process states
        exec_result = container.exec_run("ps aux")
        raw_telemetry = exec_result.output.decode("utf-8").strip()
        
        # 2. ADVANCED FEATURE: Behavioral Anomaly Inspection Logic
        # Instead of basic string matching, we parse the real Linux metrics line-by-line
        lines = raw_telemetry.split("\n")
        anomaly_score = 0
        risk_indicators = []
        
        for line in lines[1:]:  # Skip the header row
            parts = line.split()
            if len(parts) < 11:
                continue
                
            user = parts[0]      # The user executing the binary
            pid = parts[1]       # Process ID
            cpu = float(parts[2])# CPU Consumption
            command = " ".join(parts[10:]) # Full execution string
            
            # Behavioral Rule A: Administrative Shell Reconnaissance Tracking
            if user == "root" and any(cmd in command for cmd in ["cat /etc", "netstat", "ss"]):
                anomaly_score += 40
                risk_indicators.append(f"High-risk administrative discovery: PID {pid} ({command})")
                
            # Behavioral Rule B: Evasion Tracking (Processes spawned silently in background)
            if "sleep" in command or "nohup" in command:
                anomaly_score += 30
                risk_indicators.append(f"Potential execution persistence/evasion: PID {pid}")
                
            # Behavioral Rule C: Non-TTY Shell spawning
            if "sshd:" in command and "notty" in command:
                anomaly_score += 35
                risk_indicators.append(f"Rogue non-interactive shell socket verified: PID {pid}")

        # Determine detection state based on calculated anomaly thresholds
        detection_triggered = anomaly_score >= 40
        status = "DETECTED" if detection_triggered else "MISSED"
        
        # Format a highly professional analyst telemetry report for the dashboard console view
        formatted_analysis = (
            f"=== BLUE AI RUNTIME SECURITY ANALYSIS ===\n"
            f"Target Namespace   : target-node-01\n"
            f"Telemetry Source   : Linux Kernel Process Tree via Docker Socket\n"
            f"Processes Audited  : {len(lines) - 1}\n"
            f"Calculated Threat Anomaly Score: {anomaly_score}/100\n"
            f"--------------------------------------------------\n"
            f"Active Behavioral Alerts:\n"
        )
        
        if risk_indicators:
            for indicator in risk_indicators:
                formatted_analysis += f"[⚠️ RISK ALERT] {indicator}\n"
        else:
            formatted_analysis += "[✓] System baseline normal. No anomalies identified.\n"
            
        formatted_analysis += f"\n=== RAW telemetRY SNAPSHOT ===\n{raw_telemetry}"
        
        return status, formatted_analysis
            
    except Exception as e:
        error_msg = f"DOCKER CONTAINER TELEMETRY ERROR: Is 'target-node-01' running?\nDetails: {e}"
        print(f"[🔵 BLUE AI] {error_msg}")
        return "TELEMETRY_ERROR", error_msg

# ==========================================
# 3. WHITE AI ORCHESTRATOR
# ==========================================
def log_cycle_to_database(report_data):
    try:
        client = MongoClient("mongodb://127.0.0.1:27017/", serverSelectionTimeoutMS=2000)
        db = client["amcop_platform"]
        db["operation_logs"].insert_one(report_data)
        print("[⚪ WHITE AI DB] Operational metrics logged to MongoDB successfully.")
    except Exception as e:
        print(f"[⚪ WHITE AI DB] Failed to save telemetry to Database: {e}")

def run_orchestration_cycle(target_ip, target_port, user, pwd, technique):
    cycle_start = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"==================================================")
    print(f"[⚪ WHITE AI] Initializing Live Cycle at {cycle_start}")
    print(f"==================================================")
    
    # Run the live agents sequentially
    red_status, red_output = run_red_agent(target_ip, target_port, user, pwd, technique)
    
    # Small timing buffer to allow process tree state propagation
    time.sleep(1)
    
    blue_status, blue_output = run_blue_agent(target_ip, cycle_start)
    
    report_payload = {
        "timestamp": cycle_start,
        "target_host": target_ip,
        "target_port": target_port,
        "mitre_technique": technique,
        "red_outcome": red_status,
        "blue_outcome": blue_status,
        "red_raw_console": red_output,
        "blue_raw_console": blue_output,
        "system_resilience": "RESILIENT" if (red_status == "SUCCESS" and blue_status == "DETECTED") else "VULNERABLE"
    }
    
    log_cycle_to_database(report_payload)

def trigger_manual_simulation(technique_id):
    DYNAMIC_TARGET_IP = "127.0.0.1" 
    DYNAMIC_TARGET_PORT = 2222      
    TARGET_USER = "root"
    TARGET_PWD = "root"
    run_orchestration_cycle(DYNAMIC_TARGET_IP, DYNAMIC_TARGET_PORT, TARGET_USER, TARGET_PWD, technique_id)

if __name__ == "__main__":
    trigger_manual_simulation("T1087")