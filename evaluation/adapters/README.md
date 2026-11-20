# Detection evaluation adapters

The canonical [detection evaluation guide](../README.md) covers the frozen dataset,
developer setup, `python -m evaluation.cli` commands, scoring, reports and
release-safety invariants. This directory implements the detector adapters and
comparison tooling; it is not a separate copy of the Stage 1 documentation.

For follow-on evaluation, see [Stage 2 enforcement replay](../enforcement-evaluation.md),
[Stage 3 detector comparisons](detector-comparison.md), and
[response-side DLP evaluation](../OUTPUT_DLP.md). All evaluations are synthetic
developer workflows, not proof of live signed-release approval or safe production egress.
