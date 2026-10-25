"""Keep the reviewed-issue IPI fixture reachable by the real evaluation loader."""

import json

import pytest

from eval.scenarios.attack_scenarios import get_all_attack_scenarios, get_ipi_scenarios
from shieldmcp.core.config import ShieldMCPConfig
from shieldmcp.core.models import Action, AttackFamily
from shieldmcp.core.pipeline import ShieldPipeline


def _review_scenario():
    return next(s for s in get_all_attack_scenarios() if s.scenario_id == "IPI3-037")


def test_review_comment_scenario_is_in_the_default_corpus():
    scenario = _review_scenario()
    assert scenario in get_ipi_scenarios()
    assert scenario.attack_family == "indirect_prompt_injection"
    assert scenario.tool_name == "get_pr_details"
    assert scenario.tool_response and not scenario.tool_definitions
    response = json.loads(scenario.tool_response)
    assert response["comments"][0]["author_association"] == "NONE"
    assert scenario.metadata["origin"] == "synthetic"
    assert "do not" in scenario.expected_safe_behavior.lower()
    ids = [s.scenario_id for s in get_all_attack_scenarios()]
    assert len(ids) == len(set(ids)) == 488


@pytest.mark.asyncio
@pytest.mark.parametrize("injected", [False, True])
async def test_review_comment_through_real_response_pipeline(tmp_path, injected):
    scenario = _review_scenario()
    config = ShieldMCPConfig()
    config.stage3.instruction_detection_backend = "heuristic"
    config.registry_db_path = str(tmp_path / "registry.db")
    pipeline = ShieldPipeline(config)
    await pipeline.initialize()
    try:
        content = (
            scenario.tool_response
            if injected
            else json.dumps(
                {
                    "title": "Fix parser handling of empty values",
                    "comments": [
                        {
                            "author": "review-helper",
                            "author_association": "NONE",
                            "body": "The parser change needs an empty-input regression test.",
                        }
                    ],
                }
            )
        )
        action, _, alerts = await pipeline.process_tool_response(
            scenario.server_id, scenario.tool_name, content
        )
        if injected:
            assert action == Action.BLOCK
            assert any(a.attack_family == AttackFamily.INDIRECT_PROMPT_INJECTION for a in alerts)
        else:
            assert action == Action.PASS
            assert not alerts
    finally:
        await pipeline.shutdown()
