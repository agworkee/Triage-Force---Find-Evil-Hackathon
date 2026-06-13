# Judge Instructions: Try It Out!

Follow these step-by-step instructions to configure, run, and verify the TriageForce autonomous forensic triage agent.

---

## Prerequisites

- **SIFT Workstation VM**: Remote VM pre-configured with SANS forensic tools.
- **Python 3.10+**: Installed on both the local host (client) and SIFT VM (server).
- **Google Gemini API Key**: Free-tier or pay-as-you-go API key.
- **SSH Credentials**: Passwordless SSH key configuration established from the local host to the SIFT VM.

---

## SIFT VM Setup

Log in to your SIFT Workstation VM and verify that Python and the necessary forensic tool folders are staged:
```bash
# 1. Create the server deployment directory
sudo mkdir -p /opt/triageforce
sudo chown -R sansforensics:sansforensics /opt/triageforce

# 2. Set up virtual environment and install dependency requirements
python3 -m venv /opt/triageforce/venv
/opt/triageforce/venv/bin/pip install mcp

# 3. Transfer server.py to the VM
# (From your local workspace directory)
scp server/server.py sansforensics@192.168.255.128:/opt/triageforce/server.py
```

---

## Evidence Mount Instructions

Copy the target `dmz-ftp-cdrive.E01` disk image to your SIFT VM and execute the mount sequence to expose the evidence directory read-only:
```bash
# 1. Stage the raw disk file from the E01 image
sudo ewfmount /cases/case_001/image/dmz-ftp-cdrive.E01 /cases/case_001/evidence

# 2. Mount the underlying partition inside the RAW file (ewf1) to a mountpoint
sudo mkdir -p /cases/case_001/mount
sudo ntfs-3g -o ro,loop,show_sys_files,streams_interface=windows /cases/case_001/evidence/ewf1 /cases/case_001/mount

# 3. Perform a read-only bind mount to establish the secure TriageForce evidence vault
sudo mount --bind /cases/case_001/mount /cases/case_001/evidence/
sudo mount -o remount,ro,bind /cases/case_001/evidence/
```

---

## Agent Installation

On your local host, install the required packages using the requirements file:
```bash
pip install -r requirements.txt
```

Create a `.env` file in the root of your local workspace directory and populate your API key:
```env
GEMINI_API_KEY="your-actual-gemini-api-key"
```

---

## Running the Agent

### 1. Pre-Flight Diagnostic Handshake
Run the connection diagnostic command to verify Gemini authentication, SSH stdio tunnel execution, and MCP tool discovery:
```bash
python agent.py --test-connection
```

### 2. Run the Triage Loop
Execute the main autonomous triage loop to begin the investigation:
```bash
python agent.py --task "Perform full forensic triage on case_001: list all evidence files, verify integrity of available files, analyze prefetch artifacts for program execution history, analyze amcache for installed/executed programs, check shimcache for additional execution evidence, examine security event log for logon events 4624 and 4688, and produce a full correlation report mapping findings to MITRE ATT&CK techniques"
```

---

## Expected Output

When you run the agent, the console will display the following structured stages:

1. **Pre-flight Diagnostic**: Connection status, remote host credentials, and list of 12 discovered MCP tools.
2. **Investigation Plans**: Blocks starting with `[Planner] New investigation plan generated` specifying hypotheses and tools.
3. **Evidence Claims**: Structural blocks starting with `evidence_claim` showing initial findings and base confidence scores.
4. **Verification Stage**: Bounded iteration blocks starting with `[Verify H-00X]` where the agent challenges its own claims.
5. **Correlation Report**: A final terminal summary featuring:
   - Executive Summary (counts of verified, refuted, inconclusive findings).
   - Confidence Distribution.
   - **MITRE ATT&CK Summary Table** mapping tactics, techniques, and IDs.
   - Attack Narrative.
   - Chronological Timeline.

---

## Troubleshooting

- **ewf-tools Conflict**: On some SIFT installations, `apt-get install ewf-tools` can fail due to package repository conflicts. **Skip the apt install** and call the pre-installed SIFT native `ewfmount` utility directly.
- **SSH BatchMode Errors**: If the handshake fails with an SSH error, confirm that passwordless keys are configured and run the following command to verify connection parameters:
  ```bash
  ssh -o BatchMode=yes sansforensics@192.168.255.128 echo "OK"
  ```
- **UTF-8 Encoding crashes on Windows**: If you encounter a `UnicodeEncodeError` or `UnicodeDecodeError` while running check scripts or execution loops on a Windows host, enable Python's UTF-8 mode globally:
  ```powershell
  $env:PYTHONUTF8=1
  ```
