from __future__ import annotations

from .remediation_models import RemediationPlan


def render_remediation_text(plan: RemediationPlan) -> str:
    lines = [
        f"remediation: {plan.status}",
        f"minimal: {'yes' if plan.minimal else 'no'}",
        f"attempts: {plan.attempts}/{plan.max_attempts}",
    ]
    if plan.minimal_secure_upgrade_proof:
        lines.append(
            "minimal secure upgrade proof: "
            + (
                "proven"
                if plan.minimal_secure_upgrade_proof.get("proven")
                else "not proven"
            )
        )
    if plan.message:
        lines.append(f"message: {plan.message}")
    if plan.upgrades:
        issue_label = "issue" if len(plan.upgrades) == 1 else "issues"
        if plan.status in {"validated", "applied", "pull-request-created"}:
            lines.append(
                f"{len(plan.upgrades)} {issue_label} can be remediated safely"
            )
        lines.append("upgrades:")
        for upgrade in plan.upgrades:
            identifiers = ", ".join(upgrade.advisory_ids) or "policy"
            lines.append(
                "  - "
                f"{upgrade.project}: {upgrade.from_version} -> {upgrade.to_version} "
                f"({identifiers}; confidence={upgrade.compatibility_confidence})"
            )
            if upgrade.reason:
                lines.append(f"    reason: {upgrade.reason}")
            if upgrade.breaking_change_warning:
                lines.append(f"    warning: {upgrade.breaking_change_warning}")
            if upgrade.transitive_explanation:
                lines.append(f"    cause: {upgrade.transitive_explanation}")
            if upgrade.changelog_url:
                lines.append(f"    changelog: {upgrade.changelog_url}")
    if plan.blocked:
        lines.append("blocked:")
        for blocked in plan.blocked:
            lines.append(
                f"  - cannot safely remediate {blocked.project} {blocked.version}"
            )
            if blocked.advisory_ids:
                lines.append(f"    advisories: {', '.join(blocked.advisory_ids)}")
            lines.append(f"    blocker: {blocked.reason}")
            lines.append(
                "    suggested options: upgrade the constraining package, "
                "isolate the dependency, or add a temporary expiring exception"
            )
    if plan.post_fix_result is not None:
        lines.append("validation:")
        lines.append(
            "  - dependency resolution: "
            + ("passed" if plan.post_fix_result.reproduced_resolution else "failed")
        )
        if plan.post_fix_result.clean_install is not None:
            lines.append(
                "  - clean install: "
                + ("passed" if plan.post_fix_result.clean_install.passed else "failed")
            )
        if plan.post_fix_result.pip_check is not None:
            lines.append(
                "  - pip check: "
                + ("passed" if plan.post_fix_result.pip_check.passed else "failed")
            )
        for result in plan.post_fix_result.test_commands:
            lines.append(
                f"  - {result.command}: "
                + ("passed" if result.passed else "failed")
            )
        lines.append(
            "  - policy checks: "
            + ("passed" if plan.validation.policy_passed else "failed")
        )
    if plan.patches:
        lines.append("patches:")
        lines.extend(f"  - {patch.path}" for patch in plan.patches)
    if plan.patch_path:
        lines.append(f"patch written to: {plan.patch_path}")
    if plan.pull_request and plan.pull_request.url:
        lines.append(f"pull request: {plan.pull_request.url}")
    return "\n".join(lines)

