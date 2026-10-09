# 🛡️ SentinelLog & Sentinel Bank

> **Hackathon-Grade Tamper-Evident Banking Infrastructure & Real-Time SOC Audit Dashboard**  
> *Built with Schneier-Kelsey Forward-Secure HMAC Hash Chains & Real-Time Host File Watching*

---

## 🎯 Overview & Demo Scenario

This project is built for a 3-person live security simulation:

| Role | Interface | Simulation Responsibility |
| :--- | :--- | :--- |
| **Friend 1: Banking User** | `{https_url}/user` | Deposits funds, withdraws cash, sends wire transfers, inspects cryptographic receipts. |
| **Friend 2: Security Auditor** | `{https_url}/admin` | Monitors the live transaction stream, real-time hash chain integrity, and receives instant red alerts upon tampering. |
| **You: The SSH Adversary** | Terminal SSH | SSHes into the Proxmox host container and tampers with `logs/app_audit.json`. Within 1s, the SOC turns crimson red! |

> 📖 **Looking for Linux terminal hacking techniques?** See the full [Hacker Manual & Terminal Guide](HACKER_GUIDE.md) for step-by-step `sed`, `jq`, `nano`, row deletion, and truncation attacks.

---

## 🚀 Quickstart (Runs On Any System)

### Auto-Environment Setup
`start.py` automatically provisions `.venv`, installs all dependencies from `requirements.txt`, launches ngrok tunnels, and boots the self-hosted services.

#### 🪟 Windows:
```cmd
run.bat
```
*or via Python:*
```cmd
python start.py
```

#### 🐧 Linux & Proxmox Container:
```bash
# 1. Ensure python3 and python3-venv are present:
apt update && apt install -y python3 python3-venv python3-pip

# 2. Run:
chmod +x run.sh
./run.sh
```

---

## 🌐 Ngrok Tunneling & Friend Links

To generate public HTTPS links to share with your friends across the internet:

### Option A: Provide token on CLI
```bash
python start.py --ngrok-token YOUR_AUTHTOKEN
```

### Option B: Set Environment Variable
```bash
export NGROK_AUTHTOKEN="YOUR_AUTHTOKEN"  # Linux / Proxmox
set NGROK_AUTHTOKEN="YOUR_AUTHTOKEN"     # Windows
python start.py
```

### Option C: Run Locally (No Ngrok)
```bash
python start.py --no-ngrok
```

When started, the terminal displays clickable links:
```text
========================================================================
 🚀  SENTINELLOG BANK & AUDIT INFRASTRUCTURE ONLINE
========================================================================
  Local Access       : http://localhost:8000
  On-Disk Audit Log  : logs/app_audit.json (Adversary SSH target)
------------------------------------------------------------------------
  SIMULATION LINKS TO SHARE WITH YOUR FRIENDS:

  👤 FRIEND 1 (User Bank)     : https://xxxx.ngrok-free.app/user
     👉 Gives access to deposit, withdraw cash, and wire funds.

  🛡️ FRIEND 2 (Admin SOC)     : https://xxxx.ngrok-free.app/admin
     👉 Real-time audit dashboard to monitor chain integrity.
========================================================================
```

---

## 💻 Simulating The Adversary (SSH into Proxmox Container)

While Friend 1 and Friend 2 are using their web apps:

1. **SSH into your Proxmox container** from your laptop:
   ```bash
   ssh root@<proxmox-container-ip>
   cd /path/to/sentinellog
   ```

2. **Tamper with the audit log**:
   - **Method A (CLI Hacker Tool)**:
     ```bash
     python cli_hacker/attack_sim.py payload --search 50000 --replace 50
     ```
     Other CLI attack commands:
     - `python cli_hacker/attack_sim.py delete --index 1`
     - `python cli_hacker/attack_sim.py truncate --keep 2`
     - `python cli_hacker/attack_sim.py wipe`
     - `python cli_hacker/attack_sim.py reset`

   - **Method B (Direct Manual Editing)**:
     ```bash
     nano logs/app_audit.json
     ```
     Change any dollar amount (e.g. `50000.0` to `50.0`) and save (`Ctrl+O`, `Enter`, `Ctrl+X`).

3. **Observe Friend 2's Screen**:
   Within **1 second**, the Host File Watcher detects the external change, executes `verify_chain()`, and pushes a WebSocket event:
   - Admin Dashboard flashes **CRITICAL RED ALERT (SEV-1)**
   - Corrupted record is highlighted in glowing crimson with exact diagnostic proof
   - Web Audio alarm siren sounds on the auditor dashboard!

---

## 🔒 Cryptographic Architecture

SentinelLog implements the **Schneier-Kelsey Secure Audit Log Protocol**:
1. **Genesis Seed**: $y_0 = \text{SHA256}(\text{"SENTINELLOG\_GENESIS\_SEED"})$
2. **Hash Chaining**: $y_j = \text{SHA256}(y_{j-1} \parallel \text{CanonicalJSON}(D_j))$
3. **Forward-Secure Key Evolution**:
   $$K_{j+1} = \text{SHA256}(K_j)$$
   Key $K_j$ is zeroized in memory immediately with `ctypes.memset` before deriving successor $K_{j+1}$.
4. **Forward-Secure MAC**: $W_j = \text{HMAC}_{K_j}(y_j)$
5. **Root State Checkpoint**: `logs/state.json` maintains verified head state under root HMAC.

---

## 🧪 Automated Test Suite

Run the full test suite with pytest:
```bash
pytest tests/test_tamper_detection.py -v
```
All 7 unit and integration tests verify:
- Initial chain validity
- Dynamic deposits & withdrawals
- In-place payload modification detection
- Row erasure detection
- Tail truncation detection
- File wipe detection
- Baseline recovery and reseeding
