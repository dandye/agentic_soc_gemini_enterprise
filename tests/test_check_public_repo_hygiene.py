"""Unit tests for the public-repository zero-secret & zero-jargon hygiene gate."""

from __future__ import annotations

import pathlib

from scripts import check_public_repo_hygiene as hygiene


def test_allowed_templates_pass(tmp_path: pathlib.Path) -> None:
    env_example = tmp_path / ".env.example"
    env_example.write_text(
        "GCP_PROJECT_ID=<YOUR_PROJECT_ID>\n"
        "SOAR_URL=https://your-instance.siemplify-soar.com:443\n",
        encoding="utf-8",
    )
    tfvars_example = tmp_path / "terraform" / "terraform.tfvars.example"
    tfvars_example.parent.mkdir(parents=True)
    tfvars_example.write_text(
        '# Deploy into a test Google SecOps tenant\nproject_id = "your-project-id"\n',
        encoding="utf-8",
    )
    env_tfvars_example = (
        tmp_path / "terraform" / "environments" / "example.tfvars.example"
    )
    env_tfvars_example.parent.mkdir(parents=True)
    env_tfvars_example.write_text(
        'project_id = "<YOUR_PROJECT_ID>"\nmin_instances = 0\n',
        encoding="utf-8",
    )
    backend_example = tmp_path / "terraform" / "backend.tf.example"
    backend_example.write_text(
        'terraform {\n  backend "gcs" {\n    bucket = "<YOUR_TFSTATE_BUCKET>"\n  }\n}\n',
        encoding="utf-8",
    )

    assert hygiene.scan_file(env_example, repo_root=tmp_path) == []
    assert hygiene.scan_file(tfvars_example, repo_root=tmp_path) == []
    assert hygiene.scan_file(env_tfvars_example, repo_root=tmp_path) == []
    assert hygiene.scan_file(backend_example, repo_root=tmp_path) == []


def test_forbidden_paths_are_blocked() -> None:
    blocked_paths = [
        ".env",
        ".env.production",
        ".gcloud/credentials.db",
        ".terraform/terraform.tfstate",
        "terraform/terraform.tfstate",
        "terraform/terraform.tfstate.backup",
        "terraform/backend.tf",
        "terraform/prod.tfvars",
        "terraform/environments/demo.tfvars",
        "terraform/prod.tfvars.json",
        "certs/client.pem",
        "certs/private.key",
    ]
    for rel in blocked_paths:
        finding = hygiene.check_forbidden_path(rel)
        assert finding is not None, f"Expected {rel} to be blocked"


def test_secret_patterns_are_detected() -> None:
    pem = "-----BEGIN " + "RSA PRIVATE KEY-----"
    api_key = "AIza" + "Sy" + ("A" * 33)
    oauth_tok = "ya29." + ("a0AfH6SM" * 5)
    gh_pat = "ghp_" + ("B" * 36)
    client_sec = "GOCSPX-" + ("c9X" * 9)
    sa_key_id = '"private_key_id": "' + ("deadbeef" * 5) + '"'

    payload = "\n".join([pem, api_key, oauth_tok, gh_pat, client_sec, sa_key_id])
    findings = hygiene.scan_text(payload, source="sample.py", rel_path="sample.py")
    rule_ids = {f.rule_id for f in findings}

    assert "SECRET_PRIVATE_KEY" in rule_ids
    assert "SECRET_GOOGLE_API_KEY" in rule_ids
    assert "SECRET_GOOGLE_OAUTH_TOKEN" in rule_ids
    assert "SECRET_GITHUB_TOKEN" in rule_ids
    assert "SECRET_GOOGLE_OAUTH_CLIENT_SECRET" in rule_ids
    assert "SECRET_GCP_SA_KEY" in rule_ids


def test_internal_jargon_domains_and_shortlinks_are_detected() -> None:
    sandbox_word = "Arg" + "olis"
    alto_host = "user@12345." + "alto" + "strat.com"
    proxy_url = "https://airlock-proxy." + "uplink" + ".goog:999/simple"
    shortlink = "See " + "go/" + "demo-agent-governance and " + "b/" + "505412970"
    demo_proj = "project = " + "defense-" + "enterprise-1751"

    payload = "\n".join([sandbox_word, alto_host, proxy_url, shortlink, demo_proj])
    findings = hygiene.scan_text(payload, source="README.md", rel_path="README.md")
    rule_ids = {f.rule_id for f in findings}

    assert "INTERNAL_JARGON_SANDBOX" in rule_ids
    assert "INTERNAL_CORP_DOMAIN" in rule_ids
    assert "INTERNAL_SHORTLINK" in rule_ids
    assert "INTERNAL_DEMO_IDENTIFIER" in rule_ids


def test_terraform_directory_blocks_hardcoded_lab_tenants() -> None:
    tf_line = 'default = "' + "dandye-0324" + '-chronicle"\n'
    tf_findings = hygiene.scan_text(
        tf_line,
        source="terraform/variables.tf",
        rel_path="terraform/variables.tf",
    )
    assert any(f.rule_id == "TERRAFORM_HARDCODED_TENANT" for f in tf_findings)

    # Existing legacy evalsets outside terraform/ remain unaffected.
    eval_findings = hygiene.scan_text(
        tf_line,
        source="evalsets/sample.json",
        rel_path="evalsets/sample.json",
    )
    assert not any(f.rule_id == "TERRAFORM_HARDCODED_TENANT" for f in eval_findings)
