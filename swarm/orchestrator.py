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
from contextlib import AsyncExitStack
from pathlib import Path

# Allow running from project root or swarm/
sys.path.insert(0, str(Path(__file__).parent.parent))

from autogen import AssistantAgent, GroupChat, GroupChatManager, UserProxyAgent
from autogen.mcp import create_toolkit
from autogen.mcp.mcp_client import MCPClientSessionManager, StdioConfig

from config.settings import (
    DEFAULT_INCIDENT_SEVERITY,
    DEFAULT_INCIDENT_SERVICE,
    DEFAULT_INCIDENT_TIME,
    DEFAULT_JIRA_PROJECT,
    GITHUB_ORG,
    LLM_CONFIG,
)
from agents.prompts import CRITIC_PROMPT, CRITIC_SELF_CORRECT_PROMPT, DEVOPS_PROMPT, PM_PROMPT, SWE_PROMPT
from schemas.postmortem import PostMortem

MCP_DIR = Path(__file__).parent.parent / "mcp_servers"


def _install_benign_anyio_filter() -> None:
    """Silence the benign anyio 'cancel scope in a different task' RuntimeError.

    The mcp stdio client tears its anyio task group down in a different task than
    it was entered in (worsened by asyncio.gather over three sessions). This fires
    only during teardown AFTER the chat result is captured, so it is safe to drop.
    Installs a loop exception handler that chains to the previous one for anything
    else. Idempotent — safe to call on every run.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    if getattr(loop, "_ens_anyio_filter", False):
        return
    previous = loop.get_exception_handler()

    def handler(loop_, context):
        exc = context.get("exception")
        if isinstance(exc, RuntimeError) and "cancel scope" in str(exc):
            return  # benign MCP stdio teardown artifact
        if previous is not None:
            previous(loop_, context)
        else:
            loop_.default_exception_handler(context)

    loop.set_exception_handler(handler)
    loop._ens_anyio_filter = True  # type: ignore[attr-defined]


# Orchestrator

def _compute_usage(messages: list[dict]) -> dict:
    """Count tokens with tiktoken (cl100k_base); char/4 fallback if tiktoken absent."""
    text_parts = [m.get("content") or "" for m in messages]
    try:
        import tiktoken
        enc = tiktoken.get_encoding("cl100k_base")
        total_tokens = sum(len(enc.encode(t)) for t in text_parts)
    except ImportError:
        total_tokens = sum(len(t) for t in text_parts) // 4
    # Groq Llama-3.3-70B pricing: $0.59/1M input, $0.79/1M output (~75/25 split)
    estimated_cost = round(
        (total_tokens * 0.75 * 0.59 + total_tokens * 0.25 * 0.79) / 1_000_000, 6
    )
    return {
        "total_messages": len(messages),
        "estimated_tokens": total_tokens,
        "estimated_cost_usd": estimated_cost,
    }


_SPEAKER_ORDER = ["Coordinator", "DevOps_Agent", "SWE_Agent", "PM_Agent", "Critic_Agent"]


def _has_pending_tool_calls(groupchat) -> bool:
    """True if last message contains tool call suggestions not yet responded to."""
    if not groupchat.messages:
        return False
    last = groupchat.messages[-1]
    # AG2 stores tool calls in "tool_calls" key or as structured content
    if last.get("tool_calls"):
        return True
    # Also check content for the AG2 suggestion pattern
    content = last.get("content") or ""
    return "Suggested tool call" in content


def _smart_select_speaker(last_speaker, groupchat):
    """
    Ordered speaker selection that:
    1. Returns the same agent when it has pending tool call responses to handle.
    2. Blocks Critic until DEVOPS_DONE, SWE_DONE, PM_DONE all present.

    Fix: AG2 custom speaker selection fires after tool suggestions but before
    responses — without this guard, the wrong agent receives tool results.
    """
    agents_by_name = {a.name: a for a in groupchat.agents}

    # Critical: if last agent has pending tool calls, it must speak again to handle them
    if _has_pending_tool_calls(groupchat):
        return last_speaker

    full_text = " ".join(m.get("content") or "" for m in groupchat.messages)
    has_devops = "DEVOPS_DONE" in full_text
    has_swe    = "SWE_DONE"    in full_text
    has_pm     = "PM_DONE"     in full_text
    all_ready  = has_devops and has_swe and has_pm

    if last_speaker.name not in _SPEAKER_ORDER:
        return agents_by_name.get("DevOps_Agent")

    idx       = _SPEAKER_ORDER.index(last_speaker.name)
    next_name = _SPEAKER_ORDER[(idx + 1) % len(_SPEAKER_ORDER)]

    if next_name == "Critic_Agent" and not all_ready:
        if not has_devops:
            return agents_by_name["DevOps_Agent"]
        if not has_swe:
            return agents_by_name["SWE_Agent"]
        return agents_by_name["PM_Agent"]

    return agents_by_name.get(next_name)


def _should_use_swarm(service: str, incident_time: str, severity: str, context: str = "") -> bool:
    """
    Adaptive routing via learned LogisticRegression classifier (swarm/routing.py).

    Trained on ablation_v2_n4.json (N=8 scenarios × 4 repeats). Swarm is preferred
    when the classifier detects JNDI/Log4Shell-type CVEs with multi-source evidence
    alignment. Baseline preferred for resource/infra/ambiguous incidents.

    Falls back to keyword heuristic if scikit-learn is unavailable or ablation
    data has not been generated yet.
    """
    from swarm.routing import should_use_swarm as _route
    use_swarm, confidence, method = _route(service, severity, context)
    if method == "classifier":
        print(
            f"[routing] {service} → {'swarm' if use_swarm else 'baseline'} "
            f"(classifier p={confidence:.2f})",
            file=sys.stderr,
        )
    return use_swarm


async def run_incident_analysis(
    service: str,
    incident_time: str,
    severity: str,
    jira_project: str | None = None,
    seed_overrides: dict[str, str] | None = None,
) -> tuple[PostMortem | None, dict]:
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
    jira_project = jira_project or DEFAULT_JIRA_PROJECT
    _install_benign_anyio_filter()
    incident_brief = (
        f"INCIDENT REPORT\n"
        f"{'=' * 40}\n"
        f"Service:    {service}\n"
        f"Severity:   {severity}\n"
        f"Detected:   {incident_time}\n"
        f"Repo:       {GITHUB_ORG}/{service}\n"
        f"Jira proj:  {jira_project}\n"
        f"{'=' * 40}\n\n"
        f"The service is throwing errors. All three specialists must investigate "
        f"their data source and post findings. The Critic synthesises last."
    )

    env = seed_overrides or {}
    mgr = MCPClientSessionManager()

    # Holds (postmortem, usage). Computed as the LAST statement inside the
    # session block so it's already set before AsyncExitStack teardown runs.
    result: tuple[PostMortem | None, dict] | None = None

    # Open all three MCP server sessions in parallel (was sequential nested with).
    # AsyncExitStack ensures all three are cleaned up even if one fails.
    try:
      async with AsyncExitStack() as stack:
        log_session, github_session, jira_session = await asyncio.gather(
            stack.enter_async_context(
                mgr.open_session(StdioConfig(server_name="logs",   command="python", args=[str(MCP_DIR / "logs_mcp.py")],   environment=env or None))
            ),
            stack.enter_async_context(
                mgr.open_session(StdioConfig(server_name="github", command="python", args=[str(MCP_DIR / "github_mcp.py")], environment=env or None))
            ),
            stack.enter_async_context(
                mgr.open_session(StdioConfig(server_name="jira",   command="python", args=[str(MCP_DIR / "jira_mcp.py")],   environment=env or None))
            ),
        )

        log_toolkit    = await create_toolkit(log_session)
        github_toolkit = await create_toolkit(github_session)
        jira_toolkit   = await create_toolkit(jira_session)

        # Coordinator sends the brief; agents follow in round-robin order.
        coordinator = UserProxyAgent(
            name="Coordinator",
            human_input_mode="NEVER",
            code_execution_config=False,
            max_consecutive_auto_reply=0,
        )

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

        critic_agent = AssistantAgent(
            name="Critic_Agent",
            system_message=CRITIC_PROMPT,
            llm_config=LLM_CONFIG,
            human_input_mode="NEVER",
        )

        groupchat = GroupChat(
            agents=[coordinator, devops_agent, swe_agent, pm_agent, critic_agent],
            messages=[],
            # Live mode produces large real diffs and many tool calls; 30 rounds
            # can run out before the Critic synthesises. 45 gives headroom.
            max_round=45,
            speaker_selection_method=_smart_select_speaker,
        )

        chat_manager = GroupChatManager(
            groupchat=groupchat,
            llm_config=LLM_CONFIG,
            is_termination_msg=_is_postmortem_json,
        )

        await coordinator.a_initiate_chat(
            chat_manager,
            message=incident_brief,
            silent=False,
        )

        # Self-correction: if Critic's JSON is missing commits or logs, ask it to fix.
        # Keep the first valid postmortem as a floor — self-correction must never
        # make the result worse. On live data a fix commit may genuinely be
        # unreachable (e.g. GitHub GraphQL history does not page back far enough),
        # in which case the correction chat can run to max rounds without emitting
        # new JSON; we then fall back to the already-valid first answer.
        pm_first = _extract_postmortem(groupchat.messages)
        if pm_first is not None and not pm_first.inconclusive and (
            not pm_first.evidence.commits or not pm_first.evidence.logs
        ):
            await devops_agent.a_initiate_chat(
                chat_manager,
                message=CRITIC_SELF_CORRECT_PROMPT.format(
                    missing="evidence.commits" if not pm_first.evidence.commits else "evidence.logs"
                ),
                silent=False,
                clear_history=False,
            )
            pm_second = _extract_postmortem(groupchat.messages)
            pm = pm_second if pm_second is not None else pm_first
        else:
            pm = pm_first

        # Last statement inside the session block: the chat is done, so capture
        # the answer NOW. If AsyncExitStack teardown then raises the anyio
        # "cancel scope" RuntimeError, `result` is already populated.
        result = pm, _compute_usage(groupchat.messages)
    except RuntimeError as exc:
        # anyio tears MCP stdio sessions down in a task other than the one that
        # opened them (worsened by asyncio.gather). This fires AFTER the chat
        # finishes, so swallow it only when we already have a result.
        if result is None or "cancel scope" not in str(exc):
            raise

    return result if result is not None else (None, _compute_usage([]))


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

        data = None
        try:
            # raw_decode stops at end of first valid JSON object, ignoring
            # any separator lines / agent prose the Critic appended after the block.
            data, _ = json.JSONDecoder().raw_decode(raw)
        except json.JSONDecodeError as exc:
            # LLMs sometimes paste raw log/diff content with unescaped quotes or
            # control chars into a field, breaking JSON mid-string. json_repair
            # fixes the common cases (stray quotes, trailing commas, control chars)
            # so a single formatting slip does not discard an otherwise-good answer.
            print(f"[WARN] Critic JSON malformed ({exc}); attempting repair.", file=sys.stderr)
            try:
                from json_repair import repair_json
                data = json.loads(repair_json(raw))
                print("[INFO] json_repair recovered the Critic JSON.", file=sys.stderr)
            except Exception as exc2:
                print(f"[WARN] Repair failed: {exc2}", file=sys.stderr)
                print(f"[DEBUG] Raw excerpt: {raw[:300]}", file=sys.stderr)
                return None

        try:
            return PostMortem(**data)
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

    postmortem, usage = asyncio.run(
        run_incident_analysis(args.service, args.incident_time, args.severity)
    )

    if postmortem is None:
        print("\n[ERROR] Swarm did not produce a valid PostMortem.", file=sys.stderr)
        sys.exit(1)

    print(f"[ENS] Tokens (est): {usage['estimated_tokens']:,}  Cost (est): ${usage['estimated_cost_usd']:.4f}")

    output_json = postmortem.model_dump_json(indent=2)

    if args.output:
        Path(args.output).write_text(output_json, encoding="utf-8")
        print(f"\n[ENS] PostMortem written to {args.output}")
    else:
        print("\n" + "=" * 60)
        print("POST-MORTEM")
        print("=" * 60)
        print(output_json)
