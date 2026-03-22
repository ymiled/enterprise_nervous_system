"""
Swarm Orchestrator
------------------
Wires 4 AG2 agents to their respective MCP servers and runs a GroupChat
to produce a validated PostMortem JSON for a given incident.

Agent roster:
  DevOps_Agent  → logs_mcp.py   (error spikes, traces)
  SWE_Agent     → github_mcp.py (commits, diffs)
  PM_Agent      → jira_mcp.py   (tickets, prior warnings)
  Critic_Agent  → no MCP tools  (validates + emits final PostMortem JSON)

Usage:
  python swarm/orchestrator.py
  python swarm/orchestrator.py --service payment-svc --since 2021-12-10T06:15:00Z --severity P0
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

# Allow running from project root or swarm/
sys.path.insert(0, str(Path(__file__).parent.parent))

from autogen import AssistantAgent, GroupChat, GroupChatManager
from autogen.mcp import create_toolkit
from autogen.mcp.mcp_client import MCPClientSessionManager, StdioConfig

from config.settings import (
    DEFAULT_INCIDENT_SEVERITY,
    DEFAULT_INCIDENT_SERVICE,
    DEFAULT_INCIDENT_TIME,
    LLM_CONFIG,
)
from agents.prompts import CRITIC_PROMPT, CRITIC_SELF_CORRECT_PROMPT, DEVOPS_PROMPT, PM_PROMPT, SWE_PROMPT
from schemas.postmortem import PostMortem

MCP_DIR = Path(__file__).parent.parent / "mcp_servers"


# Orchestrator

async def run_incident_analysis(
    service: str,
    incident_time: str,
    severity: str,
    jira_project: str = "PAY",
    seed_overrides: dict[str, str] | None = None,
) -> PostMortem | None:
    """
    Spin up 4 agents, connect each to its MCP server, run the GroupChat,
    and return a validated PostMortem (or None if the Critic failed to produce one).

    Args:
        service:        Service name, e.g. "payment-svc"
        incident_time:  ISO-8601 timestamp of the incident
        severity:       P0–P3
        jira_project:   Jira project key for the PM agent to query
        seed_overrides: Optional env vars forwarded to MCP subprocesses to swap
                        seed data files, e.g. {"LOGS_SEED_FILE": "/path/to/oom_logs.json"}
    """
    incident_brief = (
        f"INCIDENT REPORT\n"
        f"{'=' * 40}\n"
        f"Service:    {service}\n"
        f"Severity:   {severity}\n"
        f"Detected:   {incident_time}\n"
        f"Repo:       company/{service}\n"
        f"Jira proj:  {jira_project}\n"
        f"{'=' * 40}\n\n"
        f"The service is throwing errors. All three specialists must investigate "
        f"their data source and post findings. The Critic synthesises last."
    )

    env = seed_overrides or {}
    mgr = MCPClientSessionManager()

    # Open all three MCP server sessions (each spawns a subprocess over stdio).
    # seed_overrides are passed as env vars so each server loads the right seed file.
    async with mgr.open_session(StdioConfig(server_name="logs", command="python", args=[str(MCP_DIR / "logs_mcp.py")], environment=env or None)) as log_session:
        async with mgr.open_session(StdioConfig(server_name="github", command="python", args=[str(MCP_DIR / "github_mcp.py")], environment=env or None)) as github_session:
            async with mgr.open_session(StdioConfig(server_name="jira", command="python", args=[str(MCP_DIR / "jira_mcp.py")], environment=env or None)) as jira_session:

                log_toolkit    = await create_toolkit(log_session)
                github_toolkit = await create_toolkit(github_session)
                jira_toolkit   = await create_toolkit(jira_session)

                # Agents
                devops_agent = AssistantAgent(
                    name="DevOps_Agent",
                    system_message=DEVOPS_PROMPT,
                    llm_config=LLM_CONFIG,
                    human_input_mode="NEVER",
                )
                _register_toolkit(devops_agent, log_toolkit)

                swe_agent = AssistantAgent(
                    name="SWE_Agent",
                    system_message=SWE_PROMPT,
                    llm_config=LLM_CONFIG,
                    human_input_mode="NEVER",
                )
                _register_toolkit(swe_agent, github_toolkit)

                pm_agent = AssistantAgent(
                    name="PM_Agent",
                    system_message=PM_PROMPT.format(jira_project=jira_project),
                    llm_config=LLM_CONFIG,
                    human_input_mode="NEVER",
                )
                _register_toolkit(pm_agent, jira_toolkit)

                # Critic has no tools, it reads conversation and emits PostMortem JSON
                critic_agent = AssistantAgent(
                    name="Critic_Agent",
                    system_message=CRITIC_PROMPT,
                    llm_config=LLM_CONFIG,
                    human_input_mode="NEVER",
                )

                # GroupChat
                # "round_robin" ensures each agent gets a turn to speak.
                # Termination is on the manager so it triggers the moment the
                # Critic emits the ```json block.
                groupchat = GroupChat(
                    agents=[devops_agent, swe_agent, pm_agent, critic_agent],
                    messages=[],
                    max_round=20,
                    speaker_selection_method="round_robin",
                )

                chat_manager = GroupChatManager(
                    groupchat=groupchat,
                    llm_config=LLM_CONFIG,
                    is_termination_msg=_is_postmortem_json,
                )

                await devops_agent.a_initiate_chat(
                    chat_manager,
                    message=incident_brief,
                    silent=False,
                )

                # Self-correction pass: if the Critic produced a JSON block but it
                # has empty evidence.commits or evidence.logs, ask it to fix that.
                pm = _extract_postmortem(groupchat.messages)
                if pm is not None and (not pm.evidence.commits or not pm.evidence.logs):
                    await devops_agent.a_initiate_chat(
                        chat_manager,
                        message=CRITIC_SELF_CORRECT_PROMPT.format(
                            missing="evidence.commits" if not pm.evidence.commits else "evidence.logs"
                        ),
                        silent=False,
                        clear_history=False,
                    )

    return _extract_postmortem(groupchat.messages)


# Helper functions 

def _register_toolkit(agent: AssistantAgent, toolkit) -> None:
    """
    Register all tools in a Toolkit on an agent for both LLM suggestion and execution.
      - register_for_llm:       exposes tool schemas to the LLM so it can call them
      - register_for_execution: enables the agent runtime to actually invoke them
    """
    toolkit.register_for_llm(agent)
    toolkit.register_for_execution(agent)


def _is_postmortem_json(message: dict) -> bool:
    """Termination condition: Critic has emitted a ```json block."""
    content = message.get("content", "") or ""
    return "```json" in content and message.get("name") == "Critic_Agent"


def _extract_postmortem(messages: list[dict]) -> PostMortem | None:
    """
    Walk the conversation in reverse, find the Critic's JSON block,
    parse it, and validate it against the PostMortem Pydantic schema.
    """
    for msg in reversed(messages):
        if msg.get("name") != "Critic_Agent":
            continue
        content = msg.get("content", "") or ""
        if "```json" not in content:
            continue

        start = content.find("```json") + 7
        end = content.find("```", start)
        raw = content[start:end].strip()

        try:
            data = json.loads(raw)
            return PostMortem(**data)
        except json.JSONDecodeError as exc:
            print(f"[WARN] Critic JSON is malformed: {exc}", file=sys.stderr)
            print(f"[DEBUG] Raw excerpt: {raw[:300]}", file=sys.stderr)
            return None
        except Exception as exc:
            print(f"[WARN] PostMortem validation failed: {exc}", file=sys.stderr)
            print(f"[DEBUG] Raw JSON:\n{raw}", file=sys.stderr)
            return None

    print("[WARN] No JSON block found in Critic_Agent messages.", file=sys.stderr)
    return None


# CLI 

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Enterprise Nervous System — autonomous incident root-cause analysis"
    )
    p.add_argument(
        "--service", default=DEFAULT_INCIDENT_SERVICE,
        help="Service name (default: %(default)s)",
    )
    p.add_argument(
        "--since", default=DEFAULT_INCIDENT_TIME,
        dest="incident_time",
        help="Incident start time ISO-8601 (default: %(default)s)",
    )
    p.add_argument(
        "--severity", default=DEFAULT_INCIDENT_SEVERITY,
        choices=["P0", "P1", "P2", "P3"],
        help="Incident severity (default: %(default)s)",
    )
    p.add_argument(
        "--output", default=None,
        help="Optional path to write the PostMortem JSON file",
    )
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    print(f"\n[ENS] Starting RCA swarm for {args.service} @ {args.incident_time} ({args.severity})\n")

    postmortem = asyncio.run(
        run_incident_analysis(args.service, args.incident_time, args.severity)
    )

    if postmortem is None:
        print("\n[ERROR] Swarm did not produce a valid PostMortem.", file=sys.stderr)
        sys.exit(1)

    output_json = postmortem.model_dump_json(indent=2)

    if args.output:
        Path(args.output).write_text(output_json, encoding="utf-8")
        print(f"\n[ENS] PostMortem written to {args.output}")
    else:
        print("\n" + "=" * 60)
        print("POST-MORTEM")
        print("=" * 60)
        print(output_json)
