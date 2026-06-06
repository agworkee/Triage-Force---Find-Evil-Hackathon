#!/usr/bin/env python3
"""
triageforce/agent.py
--------------------
Autonomous forensic triage agent using the Anthropic MCP Python SDK.

Connects to a remote SIFT MCP server over a passwordless SSH stdio tunnel,
runs a capped agentic loop (--max-iterations 15), performs logical consistency
checks on forensic findings, and writes a structured audit log to
agent_execution.jsonl.

Usage:
    python agent.py --task "List all files in /cases/case_001/evidence"
    python agent.py --task "Hash verify the E01 image" --max-iterations 10
    python agent.py --task "Run triage on mounted image" --dry-run
    python agent.py --test-connection                    # handshake only, no agent loop

Dependencies:
    pip install anthropic mcp

Remote MCP server is reached via passwordless SSH stdio transport:
    Host: sansforensics@192.168.255.128
    Server script: ~/triageforce/mcp_server.py  (adjust as needed)
"""

import argparse
import json
import sys
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import anthropic
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# ---------------------------------------------------------------------------
# Configuration — adjust these to match your SIFT deployment
# ---------------------------------------------------------------------------

REMOTE_HOST = "sansforensics@192.168.255.128"
REMOTE_MCP_SERVER_CMD = "sudo"
REMOTE_MCP_SERVER_ARGS = [
    "/opt/triageforce/venv/bin/python",
    "/opt/triageforce/server.py"
]

# SSH flags: BatchMode=yes ensures we fail fast if keys aren't configured
SSH_FLAGS = [
    "ssh",
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "ConnectTimeout=10",
    REMOTE_HOST,
    REMOTE_MCP_SERVER_CMD,
] + REMOTE_MCP_SERVER_ARGS

ANTHROPIC_MODEL = "claude-opus-4-5"

AUDIT_LOG_PATH = Path("agent_execution.jsonl")

DEFAULT_MAX_ITERATIONS = 15

# ---------------------------------------------------------------------------
# Audit Logger
# ---------------------------------------------------------------------------

class AuditLogger:
    """
    Writes structured JSONL entries for every significant agent event.
    Each entry includes a session ID, wall-clock timestamp, event type,
    and all relevant payload fields (tool name, args, result, token usage).
    """

    def __init__(self, log_path: Path, session_id: str) -> None:
        self.log_path = log_path
        self.session_id = session_id
        self._file = log_path.open("a", encoding="utf-8")

    def _write(self, event_type: str, payload: dict[str, Any]) -> None:
        entry = {
            "session_id": self.session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            **payload,
        }
        self._file.write(json.dumps(entry) + "\n")
        self._file.flush()

    def log_session_start(self, task: str, max_iterations: int, model: str) -> None:
        self._write("session_start", {
            "task": task,
            "max_iterations": max_iterations,
            "model": model,
            "remote_host": REMOTE_HOST,
        })

    def log_iteration(self, iteration: int) -> None:
        self._write("iteration_begin", {"iteration": iteration})

    def log_tool_call(
        self,
        iteration: int,
        tool_name: str,
        tool_use_id: str,
        arguments: dict[str, Any],
    ) -> None:
        self._write("tool_call", {
            "iteration": iteration,
            "tool_name": tool_name,
            "tool_use_id": tool_use_id,
            "arguments": arguments,
        })

    def log_tool_result(
        self,
        iteration: int,
        tool_name: str,
        tool_use_id: str,
        result: Any,
        elapsed_ms: float,
    ) -> None:
        self._write("tool_result", {
            "iteration": iteration,
            "tool_name": tool_name,
            "tool_use_id": tool_use_id,
            "result_preview": str(result)[:500],
            "elapsed_ms": round(elapsed_ms, 2),
        })

    def log_token_usage(
        self,
        iteration: int,
        input_tokens: int,
        output_tokens: int,
        cache_read: int = 0,
        cache_write: int = 0,
    ) -> None:
        self._write("token_usage", {
            "iteration": iteration,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cache_read_tokens": cache_read,
            "cache_write_tokens": cache_write,
            "total_tokens": input_tokens + output_tokens,
        })

    def log_consistency_check(
        self,
        iteration: int,
        findings: list[str],
        issues: list[str],
        passed: bool,
    ) -> None:
        self._write("consistency_check", {
            "iteration": iteration,
            "findings_count": len(findings),
            "issues": issues,
            "passed": passed,
        })

    def log_agent_decision(self, iteration: int, stop_reason: str, message: str = "") -> None:
        self._write("agent_decision", {
            "iteration": iteration,
            "stop_reason": stop_reason,
            "message": message[:300] if message else "",
        })

    def log_session_end(
        self,
        iterations_used: int,
        total_input_tokens: int,
        total_output_tokens: int,
        outcome: str,
    ) -> None:
        self._write("session_end", {
            "iterations_used": iterations_used,
            "total_input_tokens": total_input_tokens,
            "total_output_tokens": total_output_tokens,
            "total_tokens": total_input_tokens + total_output_tokens,
            "outcome": outcome,
        })

    def close(self) -> None:
        self._file.close()


# ---------------------------------------------------------------------------
# Logical Consistency Checker
# ---------------------------------------------------------------------------

def check_logical_consistency(findings: list[str]) -> tuple[bool, list[str]]:
    """
    Evaluates a list of forensic finding strings for logical contradictions
    and common integrity issues.

    Returns:
        (passed: bool, issues: list[str])
            passed=True  → no issues detected
            passed=False → issues list contains human-readable descriptions
    """
    issues: list[str] = []

    if not findings:
        return True, []

    findings_lower = [f.lower() for f in findings]

    # Rule 1: Hash mismatch contradiction
    hash_ok = any("hash match" in f or "integrity verified" in f for f in findings_lower)
    hash_fail = any("hash mismatch" in f or "integrity fail" in f for f in findings_lower)
    if hash_ok and hash_fail:
        issues.append(
            "CONTRADICTION: Findings simultaneously claim hash match AND hash mismatch. "
            "Re-verify image integrity before proceeding."
        )

    # Rule 2: Mount state contradiction
    mounted = any("mounted" in f and "read-only" in f for f in findings_lower)
    not_mounted = any("not mounted" in f or "unmounted" in f for f in findings_lower)
    if mounted and not_mounted:
        issues.append(
            "CONTRADICTION: Image reported as both mounted (read-only) and not mounted. "
            "Check ewfmount status on SIFT VM."
        )

    # Rule 3: Evidence path must be consistent across findings
    paths_mentioned = set()
    import re
    for f in findings:
        for match in re.findall(r"/[\w/._-]{5,}", f):
            paths_mentioned.add(match)
    if len(paths_mentioned) > 3:
        issues.append(
            f"WARNING: Multiple distinct paths referenced ({', '.join(list(paths_mentioned)[:5])}). "
            "Confirm all paths resolve to the same evidence mount."
        )

    # Rule 4: Timestamp plausibility (evidence older than 2000 shouldn't appear as 'recent')
    recent_and_old = (
        any("recent" in f for f in findings_lower)
        and any(("199" in f) or ("198" in f) for f in findings_lower)
    )
    if recent_and_old:
        issues.append(
            "WARNING: Findings describe old filesystem timestamps (pre-2000) as 'recent'. "
            "Review timeline logic — possible timezone or epoch parsing error."
        )

    # Rule 5: Write activity on a read-only mount
    write_on_readonly = (
        any("read-only" in f for f in findings_lower)
        and any(("file written" in f or "created file" in f or "deleted" in f) for f in findings_lower)
    )
    if write_on_readonly:
        issues.append(
            "CRITICAL: Write activity reported on a mount declared read-only. "
            "This may indicate evidence contamination — halt and review immediately."
        )

    passed = len(issues) == 0
    return passed, issues


# ---------------------------------------------------------------------------
# Core Agent Loop
# ---------------------------------------------------------------------------

async def run_agent(
    task: str,
    max_iterations: int,
    logger: AuditLogger,
    dry_run: bool = False,
) -> None:
    """
    Main agentic loop. Connects to the remote SIFT MCP server via SSH stdio
    transport, discovers available tools, then drives an Anthropic model in a
    tool-use loop until the model signals end_turn or max_iterations is hit.
    """

    anthropic_client = anthropic.Anthropic()

    server_params = StdioServerParameters(
        command=SSH_FLAGS[0],
        args=SSH_FLAGS[1:],
        env=None,
    )

    print(f"\n{'='*60}")
    print(f"  TriageForce Agent — Session {logger.session_id[:8]}")
    print(f"  Task      : {task}")
    print(f"  Max iters : {max_iterations}")
    print(f"  Remote    : {REMOTE_HOST}")
    print(f"  Dry-run   : {dry_run}")
    print(f"  Audit log : {AUDIT_LOG_PATH}")
    print(f"{'='*60}\n")

    if dry_run:
        print("[DRY-RUN] Skipping SSH connection. Tool discovery and agent loop will not run.")
        logger.log_session_end(0, 0, 0, "dry_run_skipped")
        return

    # --- Connect to remote MCP server ---
    print("[*] Connecting to remote SIFT MCP server via SSH stdio...")
    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            print("[+] MCP session initialized.")

            # Discover available tools
            tools_response = await session.list_tools()
            mcp_tools = tools_response.tools
            print(f"[+] Discovered {len(mcp_tools)} MCP tool(s): "
                  f"{', '.join(t.name for t in mcp_tools)}")

            # Convert MCP tool schemas to Anthropic tool format
            anthropic_tools = [
                {
                    "name": t.name,
                    "description": t.description or "",
                    "input_schema": t.inputSchema,
                }
                for t in mcp_tools
            ]

            # System prompt — forensic-safe constraints embedded
            system_prompt = (
                "You are a forensic triage assistant operating on a SANS SIFT workstation. "
                "The evidence image is mounted READ-ONLY at /cases/case_001/evidence. "
                "You MUST NOT invoke any tool that writes to, modifies, or deletes evidence files. "
                "When analysing findings, be precise: cite file paths, hash values, and timestamps. "
                "Structure each response as: OBSERVATION → REASONING → NEXT ACTION."
            )

            messages: list[dict[str, Any]] = [
                {"role": "user", "content": task}
            ]

            # Tracking accumulators
            all_findings: list[str] = []
            total_input_tokens = 0
            total_output_tokens = 0
            iteration = 0

            # ---- Main loop ----
            while iteration < max_iterations:
                iteration += 1
                logger.log_iteration(iteration)
                print(f"\n[Iter {iteration}/{max_iterations}] Sending to model...")

                response = anthropic_client.messages.create(
                    model=ANTHROPIC_MODEL,
                    max_tokens=4096,
                    system=system_prompt,
                    tools=anthropic_tools,
                    messages=messages,
                )

                # Token accounting
                usage = response.usage
                i_tok = usage.input_tokens
                o_tok = usage.output_tokens
                cache_r = getattr(usage, "cache_read_input_tokens", 0) or 0
                cache_w = getattr(usage, "cache_creation_input_tokens", 0) or 0
                total_input_tokens += i_tok
                total_output_tokens += o_tok
                logger.log_token_usage(iteration, i_tok, o_tok, cache_r, cache_w)
                print(f"    Tokens → in={i_tok}, out={o_tok}, "
                      f"total_session={total_input_tokens + total_output_tokens}")

                stop_reason = response.stop_reason

                # Collect text findings for consistency checker
                for block in response.content:
                    if hasattr(block, "text") and block.text:
                        all_findings.append(block.text.strip())
                        print(f"\n  [Model]: {block.text[:300]}"
                              + ("..." if len(block.text) > 300 else ""))

                # --- Consistency check every iteration ---
                passed, issues = check_logical_consistency(all_findings)
                logger.log_consistency_check(iteration, all_findings, issues, passed)
                if not passed:
                    print("\n  ⚠️  CONSISTENCY ISSUES DETECTED:")
                    for issue in issues:
                        print(f"     • {issue}")

                # --- End-turn: model is done ---
                if stop_reason == "end_turn":
                    logger.log_agent_decision(iteration, "end_turn", "Model signalled completion.")
                    print(f"\n[+] Model signalled end_turn at iteration {iteration}.")
                    break

                # --- Tool use ---
                if stop_reason == "tool_use":
                    tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
                    tool_results = []

                    for tool_block in tool_use_blocks:
                        tool_name = tool_block.name
                        tool_args = tool_block.input
                        tool_use_id = tool_block.id

                        logger.log_tool_call(iteration, tool_name, tool_use_id, tool_args)
                        print(f"\n  [Tool call] {tool_name}({json.dumps(tool_args)[:200]})")

                        t_start = time.monotonic()
                        try:
                            result = await session.call_tool(tool_name, tool_args)
                            elapsed = (time.monotonic() - t_start) * 1000
                            result_content = result.content
                            logger.log_tool_result(
                                iteration, tool_name, tool_use_id, result_content, elapsed
                            )
                            print(f"  [Tool result] ({elapsed:.0f}ms): "
                                  f"{str(result_content)[:300]}")

                            tool_results.append({
                                "type": "tool_result",
                                "tool_use_id": tool_use_id,
                                "content": str(result_content),
                            })
                        except Exception as exc:
                            elapsed = (time.monotonic() - t_start) * 1000
                            error_msg = f"Tool error: {exc}"
                            logger.log_tool_result(
                                iteration, tool_name, tool_use_id, error_msg, elapsed
                            )
                            print(f"  [Tool ERROR] {error_msg}")
                            tool_results.append({
                                "type": "tool_result",
                                "tool_use_id": tool_use_id,
                                "content": error_msg,
                                "is_error": True,
                            })

                    # Append assistant + tool results to message history
                    messages.append({"role": "assistant", "content": response.content})
                    messages.append({"role": "user", "content": tool_results})
                    continue

                # --- Unexpected stop reason ---
                logger.log_agent_decision(
                    iteration, stop_reason, f"Unexpected stop_reason: {stop_reason}"
                )
                print(f"[!] Unexpected stop_reason='{stop_reason}' at iteration {iteration}. Halting.")
                break

            else:
                # Loop exhausted without break → iteration cap hit
                print(f"\n[!] Hard iteration cap reached ({max_iterations}). Stopping agent loop.")
                logger.log_agent_decision(
                    iteration,
                    "max_iterations_reached",
                    f"Agent loop stopped after {max_iterations} iterations.",
                )

            logger.log_session_end(
                iteration, total_input_tokens, total_output_tokens, "completed"
            )
            print(f"\n{'='*60}")
            print(f"  Session complete.")
            print(f"  Iterations used : {iteration}/{max_iterations}")
            print(f"  Total tokens    : {total_input_tokens + total_output_tokens}")
            print(f"  Audit log       : {AUDIT_LOG_PATH.resolve()}")
            print(f"{'='*60}\n")


# ---------------------------------------------------------------------------
# Connection Diagnostic
# ---------------------------------------------------------------------------

async def test_connection(logger: AuditLogger) -> bool:
    """
    Establish the SSH stdio MCP handshake, discover available tools, and
    print a formatted report. Does NOT start the agent loop or call any tools.

    Returns True on success, False on any connection or protocol error.
    """
    server_params = StdioServerParameters(
        command=SSH_FLAGS[0],
        args=SSH_FLAGS[1:],
        env=None,
    )

    print(f"\n{'='*60}")
    print(f"  TriageForce — Connection Diagnostic")
    print(f"  Session  : {logger.session_id[:8]}")
    print(f"  Remote   : {REMOTE_HOST}")
    print(f"  Server   : {' '.join(REMOTE_MCP_SERVER_ARGS)}")
    print(f"{'='*60}")

    print("\n[*] Opening SSH stdio tunnel to remote SIFT MCP server...")
    t_connect_start = time.monotonic()

    try:
        async with stdio_client(server_params) as (read_stream, write_stream):
            connect_ms = (time.monotonic() - t_connect_start) * 1000
            print(f"[+] SSH process started ({connect_ms:.0f}ms)")

            async with ClientSession(read_stream, write_stream) as session:
                print("[*] Sending MCP initialize handshake...")
                t_init_start = time.monotonic()
                init_result = await session.initialize()
                init_ms = (time.monotonic() - t_init_start) * 1000

                server_name = getattr(
                    getattr(init_result, "serverInfo", None), "name", "<unknown>"
                )
                server_version = getattr(
                    getattr(init_result, "serverInfo", None), "version", "<unknown>"
                )
                print(f"[+] MCP handshake complete ({init_ms:.0f}ms)")
                print(f"    Server name    : {server_name}")
                print(f"    Server version : {server_version}")

                # Log the handshake event
                logger._write("connection_test", {
                    "status": "handshake_ok",
                    "connect_ms": round(connect_ms, 2),
                    "init_ms": round(init_ms, 2),
                    "server_name": server_name,
                    "server_version": server_version,
                    "remote_host": REMOTE_HOST,
                })

                # Discover tools
                print("\n[*] Requesting tool list from remote server...")
                t_tools_start = time.monotonic()
                tools_response = await session.list_tools()
                tools_ms = (time.monotonic() - t_tools_start) * 1000
                mcp_tools = tools_response.tools

                print(f"[+] Tool discovery complete ({tools_ms:.0f}ms) — "
                      f"{len(mcp_tools)} tool(s) found\n")

                # Pretty-print each tool with its schema
                if not mcp_tools:
                    print("  (no tools registered on remote server)")
                else:
                    for idx, tool in enumerate(mcp_tools, start=1):
                        print(f"  [{idx:02d}] {tool.name}")
                        if tool.description:
                            # Wrap long descriptions at 60 chars
                            desc = tool.description
                            for line in [desc[i:i+60] for i in range(0, len(desc), 60)]:
                                print(f"        {line}")
                        # Print input schema properties if present
                        schema = getattr(tool, "inputSchema", None) or {}
                        props = schema.get("properties", {})
                        required = set(schema.get("required", []))
                        if props:
                            print(f"        Parameters:")
                            for param_name, param_def in props.items():
                                req_marker = "*" if param_name in required else " "
                                p_type = param_def.get("type", "any")
                                p_desc = param_def.get("description", "")
                                print(f"          {req_marker} {param_name} ({p_type})"
                                      + (f" — {p_desc[:50]}" if p_desc else ""))
                        print()

                # Log tool inventory
                logger._write("connection_test", {
                    "status": "tools_discovered",
                    "tool_count": len(mcp_tools),
                    "tools_ms": round(tools_ms, 2),
                    "tool_names": [t.name for t in mcp_tools],
                })

                print(f"{'='*60}")
                print(f"  ✓ Connection diagnostic PASSED")
                print(f"  Remote server is reachable and MCP tools are visible.")
                print(f"  Run with --task \"...\" to start the agent loop.")
                print(f"{'='*60}\n")
                return True

    except Exception as exc:
        elapsed = (time.monotonic() - t_connect_start) * 1000
        print(f"\n[✗] Connection diagnostic FAILED ({elapsed:.0f}ms)")
        print(f"    Error : {exc}")
        print("\n  Troubleshooting checklist:")
        print(f"    1. SSH key available?  → ssh-add -l")
        print(f"    2. Host reachable?     → ping {REMOTE_HOST.split('@')[-1]}")
        print(f"    3. Auth works?         → ssh -o BatchMode=yes {REMOTE_HOST} echo OK")
        print(f"    4. Server script exists? → check {' '.join(REMOTE_MCP_SERVER_ARGS)}")
        print(f"    5. Venv/deps ok?       → {REMOTE_MCP_SERVER_CMD} --version on remote")
        logger._write("connection_test", {
            "status": "failed",
            "elapsed_ms": round(elapsed, 2),
            "error": str(exc),
        })
        return False


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "TriageForce — Autonomous forensic triage agent (SIFT MCP)\n\n"
            "Modes:\n"
            "  --test-connection          Handshake only: verify SSH + MCP tools, then exit\n"
            "  --task \"...\"              Run the full autonomous triage agent loop\n"
            "  --task \"...\" --dry-run    Validate config without SSH/MCP connections"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Mutually exclusive mode group
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--task",
        metavar="TASK",
        help='Forensic task to execute, e.g. "Hash verify the E01 image"',
    )
    mode_group.add_argument(
        "--test-connection",
        action="store_true",
        help=(
            "Establish the SSH stdio MCP handshake, discover remote tools, "
            "and print a diagnostic report. Does not start the agent loop."
        ),
    )

    parser.add_argument(
        "--max-iterations",
        type=int,
        default=DEFAULT_MAX_ITERATIONS,
        metavar="N",
        help=f"Hard cap on agent loop iterations (default: {DEFAULT_MAX_ITERATIONS})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="(With --task) validate config without making any SSH/MCP connections",
    )
    parser.add_argument(
        "--log",
        type=Path,
        default=AUDIT_LOG_PATH,
        help=f"Path to JSONL audit log file (default: {AUDIT_LOG_PATH})",
    )
    args = parser.parse_args()

    # --dry-run only makes sense alongside --task
    if args.dry_run and args.test_connection:
        parser.error("--dry-run cannot be combined with --test-connection")

    # Enforce iteration cap bounds (only relevant for --task)
    if args.task and (args.max_iterations < 1 or args.max_iterations > DEFAULT_MAX_ITERATIONS):
        parser.error(
            f"--max-iterations must be between 1 and {DEFAULT_MAX_ITERATIONS}. "
            f"Got: {args.max_iterations}"
        )

    session_id = str(uuid.uuid4())
    logger = AuditLogger(args.log, session_id)

    import asyncio

    # ---- Route: connection diagnostic ----
    if args.test_connection:
        logger._write("session_start", {
            "mode": "test_connection",
            "remote_host": REMOTE_HOST,
        })
        success = False
        try:
            success = asyncio.run(test_connection(logger))
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user.")
            logger._write("session_end", {"outcome": "interrupted"})
            sys.exit(1)
        except Exception:
            print("\n[FATAL ERROR during connection test]")
            traceback.print_exc()
            logger._write("session_end", {"outcome": "fatal_error"})
            sys.exit(2)
        finally:
            logger.close()  # single guaranteed close point for this branch
        sys.exit(0 if success else 1)

    # ---- Route: full agent loop (--task) ----
    logger.log_session_start(args.task, args.max_iterations, ANTHROPIC_MODEL)
    try:
        asyncio.run(
            run_agent(
                task=args.task,
                max_iterations=args.max_iterations,
                logger=logger,
                dry_run=args.dry_run,
            )
        )
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        logger.log_session_end(0, 0, 0, "interrupted")
        sys.exit(1)
    except Exception:
        print("\n[FATAL ERROR]")
        traceback.print_exc()
        logger.log_session_end(0, 0, 0, "fatal_error")
        sys.exit(2)
    finally:
        logger.close()


if __name__ == "__main__":
    main()
