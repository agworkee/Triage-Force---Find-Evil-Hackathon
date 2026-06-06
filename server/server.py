import os
import sys
import json
import subprocess
import shlex
import logging
from typing import Dict, Any, List, Optional
from mcp.server.fastmcp import FastMCP

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("triageforce")

# Initialize FastMCP Server
mcp = FastMCP("TriageForce")

# Constant definitions
EVIDENCE_BASE_DIR = "/cases"

def run_local_command(args: List[str], timeout: int = 60) -> Dict[str, Any]:
    """
    Safely executes a system command and returns structured JSON output.
    All execution parameters are validated to prevent command injection.
    """
    logger.info(f"Running command: {' '.join(args)}")
    try:
        result = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False
        )
        return {
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "status": "success" if result.returncode == 0 else "failed"
        }
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {' '.join(args)}")
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": "Command timed out after {} seconds".format(timeout),
            "status": "timeout"
        }
    except Exception as e:
        logger.error(f"Error running command: {str(e)}")
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": str(e),
            "status": "error"
        }

@mcp.tool()
def get_evidence_integrity(case_id: str, file_path: str) -> str:
    """
    Exposes sha256 checksum logic to verify file integrity on the remote SIFT workstation.
    This prevents evidence spoliation.
    """
    # Ensure safe path structure to prevent directory traversal
    safe_path = os.path.normpath(os.path.join(EVIDENCE_BASE_DIR, case_id, "evidence", file_path))
    if not safe_path.startswith(EVIDENCE_BASE_DIR):
        return json.dumps({"error": "Path traversal detected"})
        
    if not os.path.exists(safe_path):
        return json.dumps({"error": f"Evidence file not found: {file_path}"})
        
    res = run_local_command(["sha256sum", safe_path])
    if res["status"] == "success":
        parts = res["stdout"].strip().split()
        if parts:
            return json.dumps({"sha256": parts[0], "file": file_path})
    return json.dumps({"error": f"Failed to compute hash: {res['stderr']}"})

@mcp.tool()
def run_tshark_summary(case_id: str, pcap_name: str, max_conversations: int = 50) -> str:
    """
    Runs tshark analysis on a specific pcap file and structures the output.
    """
    safe_path = os.path.normpath(os.path.join(EVIDENCE_BASE_DIR, case_id, "evidence", pcap_name))
    if not safe_path.startswith(EVIDENCE_BASE_DIR):
        return json.dumps({"error": "Path traversal detected"})
        
    if not os.path.exists(safe_path):
        return json.dumps({"error": f"PCAP file not found: {pcap_name}"})
        
    # Example command to extract protocol hierarchy summary
    cmd = ["tshark", "-r", safe_path, "-q", "-z", "io,phs"]
    res = run_local_command(cmd, timeout=30)
    
    if res["status"] == "success":
        return json.dumps({
            "pcap": pcap_name,
            "protocol_hierarchy": res["stdout"].strip(),
            "error": None
        })
    else:
        return json.dumps({
            "pcap": pcap_name,
            "protocol_hierarchy": None,
            "error": res["stderr"]
        })

@mcp.tool()
def list_case_evidence(case_id: str) -> str:
    """
    Lists evidence files available in a case directory safely.
    """
    case_path = os.path.normpath(os.path.join(EVIDENCE_BASE_DIR, case_id, "evidence"))
    if not case_path.startswith(EVIDENCE_BASE_DIR):
        return json.dumps({"error": "Path traversal detected"})
        
    if not os.path.exists(case_path):
        return json.dumps({"error": f"Case directory not found: {case_id}"})
        
    try:
        files = []
        for entry in os.scandir(case_path):
            files.append({
                "name": entry.name,
                "is_dir": entry.is_dir(),
                "size": entry.stat().st_size if entry.is_file() else 0
            })
        return json.dumps({"case_id": case_id, "files": files})
    except Exception as e:
        return json.dumps({"error": str(e)})

if __name__ == "__main__":
    # When executed, start the MCP server
    mcp.run()
