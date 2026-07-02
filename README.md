# AMCOP // Advanced Multi-Agent Cyber Orchestration Platform

AMCOP (Advanced Multi-Agent Cyber Orchestration Platform) is an automated cyber range and continuous security validation engine. It utilizes an autonomous three-agent framework (Red AI, Blue AI, and White AI) to execute safe MITRE ATT&CK adversarial simulation payloads against real containerized production sandboxes, gather real-time kernel telemetry, and evaluate operational resilience continuously.

---

## 🛠️ System Architecture Overview

*   **🔴 Red AI Agent (Adversary):** Leverages automated SSH channels to execute targeted tactical discovery payloads on container hosts.
*   **🔵 Blue AI Agent (Defender):** Hooks into the Docker container socket to scrape active process trees (`ps aux`) and trace indicators of compromise (IoCs).
*   **⚪ White AI Orchestrator (C2 / State Engine):** Controls simulation scheduling, calculates defensive catch rates, writes metrics to MongoDB, and feeds the live telemetry UI via Server-Sent Events (SSE).

---

## 📋 Prerequisites & Infrastructure Requirements

Before launching the platform, ensure your local workspace has the following dependencies installed:

*   **Operating System:** Windows 10/11 (with PowerShell/WSL) or Linux/macOS
*   **Runtime Environments:** Node.js (v18+) & Python (3.10+)
*   **Containerization:** Docker Desktop running locally

---

## 🚀 Step-by-Step Deployment Guide

### Step 1: Clone the Repository
```bash
git clone [https://github.com/YOUR_USERNAME/AMCOP-MVP.git](https://github.com/YOUR_USERNAME/AMCOP-MVP.git)
cd AMCOP-MVP