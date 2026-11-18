# Milestone 5 — Detector Provenance and Portable Evidence

## Security objective

Bind each new detection result to an identifiable set of local classifier source
bytes, installed spaCy English model files, and dependency versions, then make
that *provenance claim* verifiable from the Ed25519-signed decision audit without
storing prompt text. Package the audit as a portable ZIP for offline review.

This is **provenance verification, not detection replay**. The user inputs were
intentionally discarded after processing and model weights are not embedded in
exports. A correct digest cannot prove that Presidio found every sensitive item.

## Build and runtime

`deploy/Containerfile` installs the model, then runs:

```sh
python -m tools.build_detector_manifest
python -m tools.verify_detector_manifest
```

The manifest is written inside the image at
`/service/detector-active/manifest.json`. The canonical, SHA-256 content
identity covers:

- Every regular file under the installed `en_core_web_sm` model package, with
  its relative path, byte count, and SHA-256. Generated `.pyc` caches are excluded.
- Exact source bytes for the detector, aggregator, provenance implementation,
  and its domain serialization contract.
- Python major/minor and installed versions of Presidio, spaCy, the model,
  `tldextract`, and selected spaCy NLP dependencies.

It **does not** hash the entire container image, all third-party code, the OPA
binary, or OS libraries. Reproduction still requires a trusted image/build
pipeline and the actual original model artifacts. A dependency version string
is not a supply-chain attestation. `pyproject.toml` currently uses some
version ranges, so rebuilds may legitimately produce different manifest digests.

The control plane verifies installed bytes against its build manifest before
starting and rechecks on readiness probes. A mismatched model or source file
makes the service not ready rather than silently accepting a different detector.
The manifest is copied once to the persistent audit volume under
`/var/lib/sovereign/detector-archive/<digest>.json` without replacing existing
history. The volume is shared by the offline audit-reviewer as read-only.

## Signed decision format

Each new `DetectionResult.to_dict()` includes an optional
`artifact_digest` in addition to its existing `config_digest`. They are
**different**: the config digest describes the high-level recognizer settings;
the artifact digest describes the installed model and code bytes.

The signed `DECISION` payload adds:

```json
{
  "detector_evidence_version": "1",
  "detector_snapshot": {"sha256": "<64hex>", "schema_version": 1},
  "policy_input": {
    "classification": {"detector_version": "presidio-spacy-v1", "artifact_digest": "<same 64hex>"}
  }
}
```

If the prompt was redacted and rescanned, the signed
`transformation.verification.artifact_digest` must match too. Both checks must
use the same pinned detector; a change during a request is not silently
accepted. The API and existing audit SQLite schema remain unchanged.

Older M1–M4 records have no `detector_evidence_version` and remain integrity-
verified, but cannot claim M5 detector provenance. An unavailable detector
still causes a fail-closed local decision.

## Portable evidence export

The exporter takes a consistent SQLite online backup and switches only that
**snapshot** to `journal_mode=DELETE` for the read-only reviewer. It bundles:

- Audit SQLite snapshot with signed event chain (no raw prompt by default)
- Audit verification public key (never the private key)
- Only the referenced content-addressed Rego policy snapshots
- Only the referenced content-addressed detector **manifests** (not model weights)
- Hashes/sizes of all included files and the snapshot's chain-head checkpoint

The package contains audit metadata, principal IDs, entity labels, scores and
relative offsets. This can still be sensitive metadata. Restrict distribution
and retention; do not upload to a public repository.

Example, from inside control-plane:

```sh
python -m tools.export_evidence_package \
    --out /var/lib/sovereign/m5-evidence.zip
```

The `audit-reviewer` container can run without network access:

```sh
python -m tools.verify_evidence_package --bundle /var/lib/sovereign/m5-evidence.zip
```

The default result is `EVIDENCE_PACKAGE_SELF_CONSISTENT`: a package that carries
its own verification key and checkpoint is **not independently authenticated**.
If the reviewer has a public key pinned independently of the package, provide
`--trusted-public-key /trusted/audit-key.pub.pem`; if a witnessed exact chain
head is available outside the package, also provide
`--trusted-checkpoint /trusted/checkpoint.json`. These trust anchors must be
mounted or otherwise supplied separately and must not come from the same ZIP.
A correctly pinned public key allows status `EVIDENCE_PACKAGE_VERIFIED`.
Without an external checkpoint, an attacker with the signing key could replace
history and supply a self-consistent new chain head.

## Reviewer stages

1. Reject hostile ZIP paths, excessive uncompressed sizes, duplicate names,
   and unsupported file types.
2. Verify each included file hash and byte length.
3. Compare the public signing key to an independent anchor, if supplied.
4. Verify the entire Ed25519-signed audit chain and checkpoint.
5. Resolve and validate detector manifest hashes referenced in M5 events.
6. Resolve the archived Rego bytes and replay each M4/M5 OPA decision.
7. Report counts for legacy decisions and classifications *not* replayed.

No model invocation, prompt detection, or network access occurs in the reviewer.

## Deliberate limitations and next opportunities

- No default retention of prompt values; consequently **no historical NER
  re-execution** from an audit-only export.
- No production-grade artifact-signing or build provenance framework (e.g.,
  signed SBOM, supply-chain attestations, fully pinned wheels/base images).
- Retained detector manifests can verify announced file hashes but not recreate
  deleted model binaries without separately retained model artifacts.
- If the audit writer host and signing key are compromised together, a signed
  but maliciously rewritten history is possible unless checkpoints are
  independently witnessed.
- Evidence ZIP exports should be backed by a protected workflow with operator
  approval, retention controls, and explicit authorization before distribution.
