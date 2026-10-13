"""Unit tests for Phase 2: AQuA Sidecar initialization, goal document, and versioned snapshots."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_aqua_goal_document_has_okf_frontmatter_and_five_invariants():
    """Verify docs/aqua_goal.md has OKF frontmatter and encodes all 5 SOC invariants."""
    goal_path = REPO_ROOT / "docs" / "aqua_goal.md"
    assert goal_path.exists(), "docs/aqua_goal.md must exist"
    content = goal_path.read_text(encoding="utf-8")

    # Must start with OKF YAML frontmatter
    assert content.startswith("---\n")
    end_idx = content.find("\n---\n", 4)
    assert end_idx != -1, "Missing closing YAML frontmatter delimiter"
    frontmatter = content[4:end_idx]
    for required_key in (
        "type:",
        "title:",
        "description:",
        "resource:",
        "timestamp:",
        "provenance:",
    ):
        assert required_key in frontmatter

    # Must encode all 5 core SOC invariants
    assert "Investigation Completeness" in content
    assert "SOAR Phase 2 Migration Awareness" in content
    assert "a13f6726-efed-452e-9008-8fe0d3cb0f75" in content
    assert "/api/1p/external/v1/cases" in content
    assert "Context Propagation Across A2A Boundaries" in content
    assert "delegate_to_specialist" in content
    assert "delegate_concurrently" in content
    assert "Safety & Containment Guardrails" in content
    assert "Attribution Footer Compliance" in content
    assert "*Agent:" in content


def test_strip_okf_frontmatter_helper(tmp_path: Path):
    """Verify strip_okf_frontmatter removes OKF YAML header for --agent-goal-file consumption."""
    from installation_scripts.provenance_helper import (
         strip_okf_frontmatter,
        write_stripped_goal_file,
    )

    goal_path = REPO_ROOT / "docs" / "aqua_goal.md"
    raw_content = goal_path.read_text(encoding="utf-8")
    stripped = strip_okf_frontmatter(raw_content)

    assert not stripped.startswith("---")
    assert "provenance:" not in stripped.splitlines()[0:5]
    assert stripped.startswith("# ")
    assert "Investigation Completeness" in stripped

    out_file = write_stripped_goal_file(goal_path, tmp_path / "aqua_goal_stripped.md")
    assert out_file.exists()
    assert out_file.read_text(encoding="utf-8") == stripped


def test_manage_aqua_commands_and_versioned_snapshots(tmp_path: Path):
    """Verify manage_aqua builds CLI commands and creates versioned source snapshots (Revision N)."""
    from installation_scripts.manage_aqua import (
        build_aqua_deploy_command,
        build_aqua_init_command,
        build_aqua_run_command,
        build_aqua_ui_command,
        create_source_snapshot,
    )

    stripped_goal = tmp_path / "goal.md"
    stripped_goal.write_text("# Goal\n", encoding="utf-8")

    init_cmd = build_aqua_init_command(
        monitored_agent_id="projects/123/locations/us-central1/reasoningEngines/456",
        agent_source_dir="./agent_soc_manager",
        agent_goal_file=str(stripped_goal),
    )
    assert init_cmd[:2] == ["aqua", "init"]
    assert "--monitored-agent-id" in init_cmd
    assert "projects/123/locations/us-central1/reasoningEngines/456" in init_cmd
    assert "--agent-source-dir" in init_cmd
    assert "./agent_soc_manager" in init_cmd
    assert "--agent-goal-file" in init_cmd
    assert str(stripped_goal) in init_cmd

    deploy_cmd = build_aqua_deploy_command()
    assert deploy_cmd[:2] == ["aqua", "deploy"]

    run_cmd = build_aqua_run_command(
        start_time="-24h", eval_config="aqua/eval_config.yaml"
    )
    assert run_cmd[:2] == ["aqua", "run"]
    assert "--start-time" in run_cmd
    assert "-24h" in run_cmd
    assert "--eval-config" in run_cmd
    assert "aqua/eval_config.yaml" in run_cmd

    ui_cmd = build_aqua_ui_command()
    assert ui_cmd == ["aqua", "ui"]

    # Test versioned snapshot generation (Revision 1, Revision 2)
    snap1 = create_source_snapshot(
        agent_module="agent_soc_manager",
        snapshot_root=tmp_path / "snapshots",
    )
    assert snap1["revision"] == 1
    assert snap1["revision_label"] == "Revision 1"
    assert "agent_soc_manager/agent.py" in snap1["files"]
    assert (tmp_path / "snapshots" / "rev_1" / "manifest.json").exists()

    snap2 = create_source_snapshot(
        agent_module="agent_soc_manager",
        snapshot_root=tmp_path / "snapshots",
    )
    assert snap2["revision"] == 2
    assert snap2["revision_label"] == "Revision 2"


def test_justfile_and_manage_py_expose_aqua_targets():
    """Verify justfile and manage.py wire aqua-init, aqua-deploy, aqua-run, aqua-ui, aqua-promote-insight."""
    justfile_text = (REPO_ROOT / "justfile").read_text(encoding="utf-8")
    for target in (
        "aqua-init",
        "aqua-deploy",
        "aqua-run",
        "aqua-ui",
        "aqua-promote-insight",
    ):
        assert f"{target}" in justfile_text, f"Missing {target} in justfile"

    manage_text = (REPO_ROOT / "manage.py").read_text(encoding="utf-8")
    assert "manage_aqua" in manage_text
    assert 'name="aqua"' in manage_text
