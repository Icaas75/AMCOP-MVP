# AMCOP // Autonomous Multi-Agent Cyber Operation Platform

AMCOP (Advanced Multi-Agent Cyber Orchestration Platform) is an automated cyber range and continuous security validation engine. It utilizes an autonomous three-agent framework (Red AI, Blue AI, and White AI) to execute safe MITRE ATT&CK adversarial simulation payloads against real containerized production sandboxes, gather real-time kernel telemetry, and evaluate operational resilience continuously.

---

## 🛠️ System Architecture Overview

* **🔴 Red AI Agent (Adversary):** Leverages automated SSH channels to execute targeted tactical discovery payloads on container hosts.
* **🔵 Blue AI Agent (Defender):** Hooks into the Docker container socket to scrape active process trees (`ps aux`) and trace indicators of compromise (IoCs).
* **⚪ White AI Orchestrator (C2 / State Engine):** Controls simulation scheduling, calculates defensive catch rates, writes metrics to MongoDB, and feeds the live telemetry UI via Server-Sent Events (SSE).

---

## 📋 Prerequisites & Infrastructure Requirements

Before launching the platform, ensure your local workspace has the following dependencies installed:

* **Operating System:** Windows 10/11 (with PowerShell/WSL) or Linux/macOS
* **Runtime Environments:** Node.js (v18+) & Python (3.10+)
* **Containerization:** Docker Desktop running locally

---

## 🚀 Step-by-Step Deployment Guide

### Step 1: Clone the Repository
```bash
git clone [https://github.com/YOUR_USERNAME/AMCOP-MVP.git](https://github.com/YOUR_USERNAME/AMCOP-MVP.git)
cd AMCOP-MVP
```

### Step 2: Spin Up the Infrastructure Containers
AMCOP requires a persistent datastore (MongoDB) and a live targeted asset container (target-node-01). Run the following command from your host terminal to pull images and start the network fabric:

```Bash
# Start MongoDB and your target Ubuntu endpoint
docker compose up -d
```

### Step 3: Provision Target Node Dependencies
Base containers are often stripped of diagnostic utilities. Run these commands to update the target node's system registries and install network monitoring dependencies so that the Red Agent's discovery vectors run successfully:

```Bash
docker exec -it target-node-01 apt-get update
docker exec -it target-node-01 apt-get install -y net-tools iproute2
```

### Step 4: Configure the Python Backend Engine
Navigate to your backend directory, install the required packages, and launch the asynchronous FastAPI server:

```Bash
# Navigate to backend directory
cd backend
# Install Python dependencies
pip install -r requirements.txt
```

# Start the application server
```
uvicorn main:app --reload --port 8000
```

### Step 5: Start the Frontend Cyber War Room Dashboard
Open a secondary terminal window, navigate to your frontend directory, and spin up the development environment:

```Bash
# Navigate to frontend folder
cd ../frontend
```

# Install node dependencies
```bash
npm install
```

# Launch the interactive web space
```
npm start
```
Once running, open your web browser and navigate to: http://localhost:3000
