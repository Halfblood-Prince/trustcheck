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
        lines.append("upgrades:")
        lines.extend(
            "  - "
            f"{item.project}: {item.from_version} -> {item.to_version} "
            f"({', '.join(item.advisory_ids)}; confidence={item.compatibility_confidence})"
            for item in plan.upgrades
        )
        for item in plan.upgrades:
            if item.breaking_change_warning:
                lines.append(f"    warning: {item.breaking_change_warning}")
            if item.transitive_explanation:
                lines.append(f"    cause: {item.transitive_explanation}")
            if item.changelog_url:
                lines.append(f"    changelog: {item.changelog_url}")
    if plan.blocked:
        lines.append("blocked:")
        lines.extend(
            f"  - {item.project} {item.version}: {item.reason}"
            for item in plan.blocked
        )
    if plan.patches:
        lines.append("patches:")
        lines.extend(f"  - {patch.path}" for patch in plan.patches)
    if plan.pull_request and plan.pull_request.url:
        lines.append(f"pull request: {plan.pull_request.url}")
    return "\n".join(lines)

