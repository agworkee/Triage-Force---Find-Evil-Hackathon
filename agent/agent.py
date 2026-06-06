import os
import sys
import json
import logging
from typing import Dict, Any, List

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("triageforce_agent")

class TriageForceAgent:
    """
    TriageForce agent that runs on Windows and controls SIFT via MCP commands.
    """
    def __init__(self, mcp_client=None):
        self.mcp = mcp_client
        self.case_id = None
        self.findings = []
        self.log_trace = []

    def log_action(self, action_type: str, details: Dict[str, Any]):
        """Logs action execution sequence for the judges' validation requirements."""
        trace_entry = {
            "action": action_type,
            "details": details,
            "timestamp": logging.Formatter("%(asctime)s").format(logging.LogRecord("", 0, "", 0, "", [], None))
        }
        self.log_trace.append(trace_entry)
        logger.info(f"Action Logged: {action_type} - {list(details.keys())}")

    def run_triage(self, case_id: str):
        """Runs the self-correcting triage agent sequence."""
        self.case_id = case_id
        self.log_action("start_triage", {"case_id": case_id})
        
        # 1. Gather evidence list
        logger.info(f"Querying evidence for case: {case_id}")
        # Note: Actual MCP tool invocation will be linked here
        
        # 2. Sequential analysis & self-correction placeholder loop
        logger.info("Starting analysis sequence...")
        
        # 3. Save logs and generate final triage report
        self.save_execution_logs()

    def save_execution_logs(self):
        """Saves execution logs in JSONL format for judges' review."""
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, f"{self.case_id}_execution.jsonl")
        
        with open(log_file, "w") as f:
            for entry in self.log_trace:
                f.write(json.dumps(entry) + "\n")
        logger.info(f"Execution trace saved successfully to {log_file}")

if __name__ == "__main__":
    agent = TriageForceAgent()
    agent.run_triage("case_001")
