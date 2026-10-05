from __future__ import annotations

import re


_AGENT_ID_RE = re.compile(r"^[0-9]{1,8}$")


def parse_wazuh_agent_list(value: str) -> list[str]:
    """Return an explicitly scoped Wazuh agent list.

    Active response must never default to a fleet-wide target.
    """
    agents = [item.strip() for item in value.split(",") if item.strip()]
    if not agents:
        raise ValueError("WAZUH_ACTIVE_RESPONSE_AGENTS must list at least one Wazuh agent id")
    if any(agent.casefold() in ("all", "*") for agent in agents):
        raise ValueError("WAZUH_ACTIVE_RESPONSE_AGENTS must list explicit agent ids, not 'all' or '*'")
    if any(not _AGENT_ID_RE.fullmatch(agent) for agent in agents):
        raise ValueError("WAZUH_ACTIVE_RESPONSE_AGENTS must contain numeric Wazuh agent ids such as 001,002")
    return agents
