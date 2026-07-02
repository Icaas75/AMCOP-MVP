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
# 2. REAL BLUE AI AGENT
# ==========================================
def run_blue_agent(target_ip, attack_timestamp):
    print(f"\n[🔵 BLUE AI] Analyzing security events for target: {target_ip}")
    
    try:
        client = docker.from_env()
        # Connects to your real, running local target node container
        container = client.containers.get("target-node-01")
        
        print(f"[🔵 BLUE AI] Inspecting live active process telemetry trees...")
        exec_result = container.exec_run("ps aux")
        raw_telemetry = exec_result.output.decode("utf-8").strip()
        
        # Threat signature tracking: look for interactive signatures or discovery tools
        signatures = ["sshd", "passwd", "netstat", "ss"]
        
        detection_triggered = False
        for sig in signatures:
            if sig in raw_telemetry:
                detection_triggered = True
                break
                
        status = "DETECTED" if detection_triggered else "MISSED"
        return status, raw_telemetry
            
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