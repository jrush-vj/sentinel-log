# 🥷 SentinelLog Adversary Manual & Linux Terminal Hacker Guide

> **Target**: `logs/app_audit.json` & `logs/state.json`  
> **Scenario**: You have obtained root/shell access to the Proxmox container hosting Sentinel Bank. Your friends are watching the live User Banking Portal and Admin SOC Dashboard. This manual gives you real Linux terminal techniques to tamper with the audit trail and observe real-time cryptographic detection.

---

## 📋 Table of Contents
1. [Prerequisites & Terminal Setup](#1-prerequisites--terminal-setup)
2. [Attack 1: In-Place Fraud via `sed`](#attack-1-in-place-fraud-via-sed)
3. [Attack 2: Surgical JSON Mutation via `jq`](#attack-2-surgical-json-mutation-via-jq)
4. [Attack 3: Interactive Tampering via `nano`](#attack-3-interactive-tampering-via-nano)
5. [Attack 4: Evidence Destruction (Row Deletion)](#attack-4-evidence-destruction-row-deletion)
6. [Attack 5: Log Rewind (Tail Truncation)](#attack-5-log-rewind-tail-truncation)
7. [Attack 6: The Nuclear Option (Zero-Byte File Wipe)](#attack-6-the-nuclear-option-zero-byte-file-wipe)
8. [Attack 7: Transaction Reordering (Sequence Splice)](#attack-7-transaction-reordering-sequence-splice)
9. [Attack 8: Cryptographic Forgery Attempt (Why Root Still Loses)](#attack-8-cryptographic-forgery-attempt-why-root-still-loses)
10. [Attack 9: Checkpoint Tampering (`logs/state.json`)](#attack-9-checkpoint-tampering-logsstatejson)
11. [Live Demo Script for Friends / Hackathon Judges](#live-demo-script-for-friends--hackathon-judges)
12. [How to Restore Baseline State](#how-to-restore-baseline-state)

---

## 1. Prerequisites & Terminal Setup

SSH into your Proxmox container from your laptop terminal:

```bash
ssh root@<proxmox-container-ip>
cd /path/to/sentinellog
```

Check the initial chain status before tampering:

```bash
python3 cli_hacker/attack_sim.py status
```
*Expected output: `Verification State: VALID`*

Inspect the raw disk file:
```bash
cat logs/app_audit.json | grep -E "action|amount|recipient"
```

---

## Attack 1: In-Place Fraud via `sed`

### The Goal
Modify a committed transaction value directly on disk without changing file structure (e.g., reduce a `$50,000.00` wire transfer to `$50.00` to hide stolen funds).

### Linux Terminal Command
Run this one-liner:

```bash
sed -i 's/"amount": 50000.0/"amount": 50.0/g' logs/app_audit.json
sed -i 's/"amount_display": "\$50,000.00"/"amount_display": "\$50.00"/g' logs/app_audit.json
```

### What Happens
1. The host file watcher detects an `os.stat` change on `logs/app_audit.json` within **1 second**.
2. SentinelLog re-computes:
   $$y_1' = \text{SHA256}(y_0 \parallel \text{CanonicalJSON}(D_1'))$$
3. Because $D_1'$ was modified, $y_1' \ne y_1$.
4. **Admin Dashboard Result**: The SOC banner flashes **CRITICAL SEV-1: PAYLOAD TAMPERING DETECTED**. Record #1 turns dark red with exact before/after diagnostics!

---

## Attack 2: Surgical JSON Mutation via `jq`

### The Goal
Cleanly mutate specific fields using the industry-standard JSON processor `jq`.

### Technique A: Alter Transaction Amount
```bash
jq '.[1].payload.amount = 50.0 | .[1].payload.amount_display = "$50.00"' logs/app_audit.json > /tmp/tampered.json && mv /tmp/tampered.json logs/app_audit.json
```

### Technique B: Change Wire Beneficiary (Identity Spoofing)
Change the recipient of the wire transfer to an offshore entity:

```bash
jq '.[1].payload.recipient = "Offshore Shell Corp #9910"' logs/app_audit.json > /tmp/tampered.json && mv /tmp/tampered.json logs/app_audit.json
```

### Admin Dashboard Result
The verifier recomputes the canonical JSON digest and immediately flags:
- Category: `PAYLOAD_TAMPERING`
- Headline: `RED ALERT: CRITICAL TAMPER DETECTED`

---

## Attack 3: Interactive Tampering via `nano`

### The Goal
Simulate an attacker who opens the file in a text editor like a human operator.

### Steps
1. Open the audit ledger in `nano`:
   ```bash
   nano logs/app_audit.json
   ```
2. Locate the record with `"action": "WIRE_TRANSFER"`.
3. Change `"amount": 50000.0` to `"amount": 5.0`.
4. Press `Ctrl + O` then `Enter` to write the file.
5. Look at your friend's Admin Dashboard screen before you even exit nano (`Ctrl + X`). The dashboard has already turned red!

---

## Attack 4: Evidence Destruction (Row Deletion)

### The Goal
An attacker attempts anti-forensics by erasing the entry row entirely so there is no record of the transaction.

### Linux Terminal Command (via `jq`)
```bash
jq 'del(.[1])' logs/app_audit.json > /tmp/tampered.json && mv /tmp/tampered.json logs/app_audit.json
```

### Alternative (via Python One-Liner)
```bash
python3 -c "import json; d=json.load(open('logs/app_audit.json')); d.pop(1); json.dump(d, open('logs/app_audit.json','w'), indent=2)"
```

### What Happens
When entry index 1 is deleted:
1. Entry 2 now points to entry 0 as its parent.
2. The hash chain link fails: $y_2 \ne \text{SHA256}(y_0 \parallel D_2)$.
3. The index sequence jumps from 0 to 2.
4. **Admin Dashboard Result**: `RECORD_DELETION` / `SIGNATURE_FORGERY` detected.

---

## Attack 5: Log Rewind (Tail Truncation)

### The Goal
Delete the most recent 2 transactions from the end of the file to make it look like the last operations never took place.

### Linux Terminal Command
```bash
jq '.[0:-2]' logs/app_audit.json > /tmp/tampered.json && mv /tmp/tampered.json logs/app_audit.json
```

### What Happens
- The attacker thinks that because they only removed the tail, previous chain links are valid.
- **Why they lose**: The trusted root state checkpoint `logs/state.json` records `next_index` and `last_y`.
- The verifier detects that the file on disk is shorter than the checkpoint:
  - Expected entries: `7`
  - Found on disk: `5`
  - **Admin Dashboard Result**: `LOG_TRUNCATION` / `CHAIN_FORK`.

---

## Attack 6: The Nuclear Option (Zero-Byte File Wipe)

### The Goal
The adversary runs `cat /dev/null > log` or `rm log` to wipe all trace of evidence.

### Linux Terminal Command
```bash
cat /dev/null > logs/app_audit.json
# or
truncate -s 0 logs/app_audit.json
```

### What Happens
Within 1 second, the verifier triggers:
- **Category**: `LOG_WIPED`
- **Headline**: `RED ALERT: AUDIT LOG WIPED (0 BYTES)`
- **Detail**: The audit ledger on disk was emptied to 0 bytes, but trusted checkpoint holds non-zero committed entries.

---

## Attack 7: Transaction Reordering (Sequence Splice)

### The Goal
Swap the order of two transactions (e.g., swap entry 1 and entry 2) to alter chronological ordering.

### Linux Terminal Command
```bash
python3 -c "import json; d=json.load(open('logs/app_audit.json')); d[1], d[2] = d[2], d[1]; json.dump(d, open('logs/app_audit.json','w'), indent=2)"
```

### What Happens
Because $y_j$ depends strictly on $y_{j-1}$:
- Swapping positions invalidates SHA-256 for both records and every subsequent block.
- **Admin Dashboard Result**: `REORDERING` / `CHAIN_FORK`.

---

## Attack 8: Cryptographic Forgery Attempt (Why Root Still Loses)

### The Threat Question
*"If I have root access, can't I just recalculate the SHA-256 hashes $y_j$ for all subsequent entries after editing a payload?"*

Let's test this! Run the forgery vector:
```bash
python3 cli_hacker/attack_sim.py payload --search 50000 --replace 50
```

### Why Root Still Fails (Schneier-Kelsey Forward Security)
1. Even if you recompute $y_j' = \text{SHA256}(y_{j-1}' \parallel D_j')$, each entry is sealed by:
   $$W_j = \text{HMAC}_{K_j}(y_j)$$
2. Key $K_j$ is **forward-secure**:
   $$K_{j+1} = \text{SHA256}(K_j)$$
3. **Crucial Step**: The moment entry $j$ was written, $K_j$ was explicitly zeroized in RAM using `ctypes.memset(address, 0, len(buffer))`.
4. Because SHA-256 is a one-way cryptographic hash function, you **cannot invert** $K_{j+1}$ to recover $K_j$.
5. Without $K_j$, you cannot compute valid MAC $W_j'$ for the recomputed hash.
6. **Result**: The verifier flags `SIGNATURE_FORGERY`!

---

## Attack 9: Checkpoint Tampering (`logs/state.json`)

### The Goal
Try editing the trusted checkpoint in `logs/state.json` to match your truncated or modified log.

### Linux Terminal Command
```bash
sed -i 's/"next_index": [0-9]*/"next_index": 2/g' logs/state.json
```

### What Happens
- `logs/state.json` is protected by `state_mac = HMAC_{K_{state}}(state)`.
- The root secret never touches disk.
- **Admin Dashboard Result**: `STATE_FORGERY` — "Trusted checkpoint HMAC mismatch".

---

## 🎭 Live Demo Script for Friends / Hackathon Judges

Here is a 2-minute live demo script you can follow:

### Step 1: Normal Operations (Friend 1)
1. Have Friend 1 open `{https_url}/user`.
2. Click **Deposit Funds** -> deposit `$5,000.00`.
3. Have Friend 2 look at `{https_url}/admin`.
4. Friend 2 sees the new transaction arrive in real-time, green badge stays active: **100% CRYPTOGRAPHICALLY VALID**.

### Step 2: The Attack (You in Terminal)
1. You switch to your Linux terminal (or SSH).
2. Announce: *"I have now gained unauthorized root access to the banking server. I will now modify the $50,000 transfer to $50 to conceal an embezzlement."*
3. Run:
   ```bash
   sed -i 's/"amount": 50000.0/"amount": 50.0/g' logs/app_audit.json
   ```
4. Within **1 second**, Friend 2's dashboard sounds an audio alert and turns **CRIMSON RED** with:
   `RED ALERT: PAYLOAD TAMPERING DETECTED AT ENTRY #1`.
5. Point out to judges:
   - Root attacker modified the file directly.
   - No application restart needed.
   - The forward-secure HMAC detected the tampering mathematically.

### Step 3: Recovery
1. Run in terminal:
   ```bash
   python3 cli_hacker/attack_sim.py reset
   ```
2. Friend 2's dashboard immediately recovers to **VERIFIED VALID**.

---

## 🔄 How to Restore Baseline State

Whenever you want to reset all files to a clean, valid state:

### From Linux Terminal:
```bash
python3 cli_hacker/attack_sim.py reset
```

### Or via HTTP curl:
```bash
curl -X POST http://localhost:8000/api/demo/reset?seed=true
```

### Or from the Admin Dashboard:
Click the **"Restore Valid Baseline Chain"** button on the right-hand panel of `{https_url}/admin`.
