# Recommendation model

The default text output is optimized for operators. It starts with a concise summary and then expands into evidence and risk details.

## Recommendation tiers

### `verified`

Every discovered release artifact verified successfully.

### `metadata-only`

No cryptographically verified artifact set was established, but no risk flags elevated the result.

### `review-required`

Medium-severity issues require manual review.

This can include cases where a package publishes no provenance at all. Missing provenance weakens the trust signal, but it is different from a failed verification or a direct inconsistency.

### `high-risk`

High-severity issues were detected.

## Related report sections

A recommendation is best interpreted together with:

- `coverage`
- `publisher_trust`
- `provenance_consistency`
- `release_drift`
- `dependency_summary`
- `dependencies`
- `risk_flags`
- `policy`

## Important distinction

A recommendation is not the same thing as a policy gate. A report can have an advisory recommendation and still pass or fail depending on the selected policy settings.

When dependency inspection is enabled, dependency outcomes can also influence the top-level recommendation. For example, a package with clean top-level release evidence may still become `review-required` or `high-risk` if an inspected dependency lands in one of those tiers.
