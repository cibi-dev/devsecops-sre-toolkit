import pytest
from postmortem.rca_engine import (
    ActionItemPriority,
    ActionItemType,
    ContributingFactorCategory,
    FiveWhys,
    RCAEngine,
    RCAResult,
)


def test_build_5_whys():
    engine = RCAEngine()
    problem = "API Gateway returned 504 Gateway Timeout for 25 minutes"
    whys = [
        "Upstream auth service stopped responding to health checks",
        "Connection pool on the auth service was exhausted",
        "A slow database query locked rows in the sessions table",
        "A migration script ran without an index on session_token column",
        "Deployment checklist lacked pre-migration index verification gate",
    ]
    result = engine.build_5_whys(problem, whys)

    assert result.problem_statement == problem
    assert len(result.why_chain) == 5
    assert result.root_cause == whys[-1]


def test_contributing_factors():
    engine = RCAEngine()
    f1 = engine.add_contributing_factor(
        category=ContributingFactorCategory.INFRASTRUCTURE,
        description="Database replica lag exceeded 60s under peak morning traffic",
        impact="HIGH",
    )
    f2 = engine.add_contributing_factor(
        category=ContributingFactorCategory.MONITORING,
        description="Alert threshold for connection pool exhaustion was set too high (95%)",
        impact="MEDIUM",
    )

    assert len(engine.contributing_factors) == 2
    assert f1.category == "INFRASTRUCTURE"
    assert f2.category == "MONITORING"


def test_action_items_generation():
    engine = RCAEngine()
    act1 = engine.add_action_item(
        description="Add automated pre-commit index verification in CI pipeline",
        item_type=ActionItemType.PREVENTATIVE,
        owner="DBA Team",
        priority=ActionItemPriority.P0,
        target_date="2026-09-05",
    )
    act2 = engine.add_action_item(
        description="Lower connection pool alert threshold from 95% to 75%",
        item_type=ActionItemType.DETECTIVE,
        owner="SRE Team",
        priority=ActionItemPriority.P1,
    )

    assert act1.id == "ACT-001"
    assert act1.priority == "P0"
    assert act2.id == "ACT-002"
    assert act2.item_type == "DETECTIVE"
    assert act2.status == "OPEN"


def test_team_reflections():
    engine = RCAEngine()
    engine.add_reflection(
        well=["On-call engineer acknowledged page within 2 minutes", "Runbook for failover was clear"],
        poorly=["Metrics dashboard took 8 minutes to load due to high cardinality"],
        lucky=["The incident happened after peak market trading hours"],
    )

    assert len(engine.what_went_well) == 2
    assert len(engine.what_went_poorly) == 1
    assert len(engine.where_we_got_lucky) == 1


def test_evaluate_blamelessness_clean():
    engine = RCAEngine()
    clean_text = "The connection pool exhausted when database queries experienced lock contention due to missing indexing."
    eval_res = engine.evaluate_blamelessness(clean_text)

    assert eval_res["is_blameless"] is True
    assert eval_res["score"] == 100.0
    assert len(eval_res["flagged_terms"]) == 0


def test_evaluate_blamelessness_flagged():
    engine = RCAEngine()
    blame_text = "The outage was caused by human error because the careless developer forgot to check the index."
    eval_res = engine.evaluate_blamelessness(blame_text)

    assert eval_res["is_blameless"] is False
    assert eval_res["score"] < 100.0
    assert len(eval_res["flagged_terms"]) >= 2
    assert len(eval_res["recommendations"]) >= 2
    assert any("Replace blame phrasing" in r for r in eval_res["recommendations"])


def test_generate_rca_result():
    engine = RCAEngine()
    engine.build_5_whys("Service crashed", ["Memory leak", "Buffer not freed"])
    engine.add_action_item("Fix buffer management", priority=ActionItemPriority.P0)
    rca: RCAResult = engine.generate_rca_result(
        trigger_event="Surge in payload size from partner API",
        root_cause_summary="Buffer allocation without maximum byte limit",
    )

    assert rca.trigger_event == "Surge in payload size from partner API"
    assert rca.root_cause_summary == "Buffer allocation without maximum byte limit"
    assert len(rca.action_items) == 1
    assert rca.five_whys is not None
