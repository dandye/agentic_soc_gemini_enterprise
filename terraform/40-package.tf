# Verifies deterministic source-tree hashes for all governed SecOps agent
# archives (`terraform/dist/<name>.tar.gz`) at plan time.

locals {
  core_agent_names = toset([
    "cti_researcher",
    "threat_hunter",
    "detection_engineer",
    "tier2_responder",
    "soc_orchestrator",
  ])

  all_agent_names = toset([
    "cti_researcher",
    "threat_hunter",
    "detection_engineer",
    "tier2_responder",
    "wizard_agent",
    "soc_orchestrator",
  ])

  agent_names = var.enable_wiz_mcp ? local.all_agent_names : local.core_agent_names

  agents_dir        = "${path.module}/../governed_agents"
  shared_guards_dir = "${local.agents_dir}/shared_decision_guards"
  dist_dir          = "${path.module}/dist"

  shared_guard_files = [
    for f in fileset(local.shared_guards_dir, "**") : "shared_decision_guards/${f}"
    if !can(regex("(^|/)__pycache__/", f)) && !can(regex("\\.py[co]$", f))
  ]

  agent_own_files = {
    for name in local.all_agent_names : name => [
      for f in fileset("${local.agents_dir}/${name}", "**") : f
      if !can(regex("(^|/)__pycache__/", f)) && !can(regex("\\.py[co]$", f))
    ]
  }

  agent_source_files = {
    for name in local.all_agent_names : name => sort(concat(
      local.agent_own_files[name],
      local.shared_guard_files,
    ))
  }

  agent_source_hash = {
    for name, files in local.agent_source_files : name => sha256(join("", [
      for f in files : "${f}\n${filesha256("${local.agents_dir}/${startswith(f, "shared_decision_guards/") ? f : "${name}/${f}"}")}\n"
    ]))
  }

  agent_packaged_hash = {
    for name in local.all_agent_names :
    name => try(trimspace(file("${local.dist_dir}/${name}.sha256")), "")
  }

  agent_source_archive = {
    for name in local.all_agent_names :
    name => try(filebase64("${local.dist_dir}/${name}.tar.gz"), "")
  }

  agent_package_ok = {
    for name in local.all_agent_names :
    name => (
      local.agent_packaged_hash[name] == local.agent_source_hash[name]
      && local.agent_source_archive[name] != ""
    )
  }

  agent_package_error = {
    for name in local.all_agent_names : name => join("", [
      "terraform/dist/${name}.tar.gz is missing or stale. Run:\n\n",
      "    ./scripts/governance/package_agent.sh all\n\n",
      "expected source hash ${local.agent_source_hash[name]}, ",
      "dist/${name}.sha256 has ${local.agent_packaged_hash[name] == "" ? "(absent)" : local.agent_packaged_hash[name]}",
    ])
  }
}

resource "terraform_data" "package" {
  for_each = local.agent_names

  input = {
    agent       = each.key
    source_hash = local.agent_source_hash[each.key]
  }

  triggers_replace = {
    source_hash = local.agent_source_hash[each.key]
  }

  provisioner "local-exec" {
    command = "bash \"${path.module}/../scripts/governance/package_agent.sh\" ${each.key}"
  }
}
