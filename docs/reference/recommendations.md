# Recommendation model

The default text output is optimized for operators. It starts with a concise summary and then expands into evidence and risk details.

## Recommendation tiers

### `verified`

Every discovered release artifact verified successfully.

### `metadata-only`

No cryptographically verified artifact set was established, but no risk flags elevated the result.

### `review-required`

Medium-severity issues require manual review.

### `high-risk`

High-severity issues were detected.

## Related report sections

A recommendation is best interpreted together with:

- `coverage`
- `publisher_trust`
- `provenance_consistency`
- `release_drift`
- `risk_flags`
- `policy`

## Important distinction

A recommendation is not the same thing as a policy gate. A report can have an advisory recommendation and still pass or fail depending on the selected policy settings.
