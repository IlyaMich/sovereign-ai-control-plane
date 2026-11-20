"""Milestone 5: provenance, archive consistency and offline package security."""

import hashlib
import json
import sqlite3
import zipfile
from contextlib import closing

import pytest

from app.audit.evidence_package import (
    EvidencePackageError,
    _manifest_of,
    export_package,
    verify_package,
)
from app.detection.evidence import DetectorEvidenceError, verify_detector_references
from app.detection.provenance import (
    DetectorIntegrityError,
    archive_manifest,
    digest_payload,
    find_archived,
    verify_manifest,
)
from app.domain.contracts import DetectionResult, DetectionStatus, Finding, Sensitivity
from app.policy.replay import replay_database


def detector_manifest():
    payload = {
        "schema_version": 1,
        "detector_version": "presidio-spacy-v1",
        "model": {"name": "en_core_web_sm", "version": "3.8.0"},
        "python": "3.12",
        "dependency_versions": {"spacy": "3.8.0"},
        "files": [
            {"path": "model/config.cfg", "size": 1, "sha256": "a" * 64},
            {"path": "source/app/detection/presidio_detector.py", "size": 3, "sha256": "b" * 64},
        ],
    }
    return {**payload, "digest": digest_payload(payload)}


def commit_m5(audit, digest, *, transformed=False):
    classification = DetectionResult(
        DetectionStatus.PRIVATE,
        Sensitivity.MEDIUM,
        (Finding("EMAIL_ADDRESS", 0, 4, "synthetic", 1.0),),
        ("EMAIL_ADDRESS",),
        "presidio-spacy-v1",
        (),
        "cfg",
        digest,
    )
    audit.commit(
        "r1",
        "t1",
        "DECISION",
        {
            "policy_input": {"classification": classification.to_dict()},
            "decision": {
                "effect": "DENY",
                "obligations": [],
                "reason_codes": ["DEFAULT_DENY"],
                "policy_revision": "local",
            },
            "detector_evidence_version": "1",
            "detector_snapshot": {"sha256": digest, "schema_version": 1},
            "transformation": {
                "applied": transformed,
                "verification": (classification.to_dict() if transformed else None),
            },
        },
    )
    audit.commit("r1", "t1", "OUTCOME", {"execution_status": "BLOCKED", "model_invoked": False})


def test_manifest_recalculates_its_identity():
    m = detector_manifest()
    assert verify_manifest(m) == m["digest"]
    m["dependency_versions"]["spacy"] = "9.0"
    with pytest.raises(DetectorIntegrityError):
        verify_manifest(m)


def test_manifest_rejects_unsorted_and_malformed_file_paths():
    m = detector_manifest()
    m["files"].reverse()
    with pytest.raises(DetectorIntegrityError):
        verify_manifest(m)
    m = detector_manifest()
    m["files"][0]["path"] = "model/../secrets"
    with pytest.raises(DetectorIntegrityError):
        verify_manifest(m)


def test_archive_is_non_overwriting(tmp_path):
    m = detector_manifest()
    path = archive_manifest(m, tmp_path)
    assert find_archived(tmp_path, m["digest"]) == m
    assert archive_manifest(m, tmp_path) == path
    path.write_text("{}")
    with pytest.raises(DetectorIntegrityError):
        archive_manifest(m, tmp_path)
    with pytest.raises(DetectorIntegrityError):
        find_archived(tmp_path, m["digest"])


def test_detected_artifact_identity_in_domain_serialization():
    r = DetectionResult(
        DetectionStatus.UNKNOWN, Sensitivity.UNKNOWN, (), (), "unknown", artifact_digest="c" * 64
    )
    assert r.to_dict()["artifact_digest"] == "c" * 64
    assert "artifact_digest" not in DetectionResult.unknown().to_dict()


def test_offline_verifier_follows_signed_detector_reference(tmp_path, audit):
    m = detector_manifest()
    archive_manifest(m, tmp_path / "detectors")
    commit_m5(audit, m["digest"], transformed=True)
    result = verify_detector_references(str(audit.db_path), str(tmp_path / "detectors"))
    assert result["detector_provenance_verified"] == 1
    assert result["classification_replayed"] == 0
    result = replay_database(
        str(audit.db_path),
        str(audit.key_path.with_suffix(".pub.pem")),
        str(tmp_path / "policies"),
        evaluator=lambda *_: {},
        detector_archive_root=str(tmp_path / "detectors"),
    )
    assert result["detector_provenance_verified"] == 1
    assert result["policy_decisions_replayed"] == 0


def test_missing_detector_archive_fails_closed(tmp_path, audit):
    m = detector_manifest()
    commit_m5(audit, m["digest"])
    with pytest.raises(DetectorEvidenceError):
        verify_detector_references(str(audit.db_path), str(tmp_path / "missing"))


def test_mismatched_archive_digest_fails_closed(tmp_path, audit):
    m = detector_manifest()
    archive_manifest(m, tmp_path / "detectors")
    commit_m5(audit, "f" * 64)
    with pytest.raises(DetectorEvidenceError):
        verify_detector_references(str(audit.db_path), str(tmp_path / "detectors"))


def test_rejects_post_redaction_verifier_using_other_detector(tmp_path, audit):
    m = detector_manifest()
    archive_manifest(m, tmp_path / "detectors")
    audit.commit(
        "r1",
        "t1",
        "DECISION",
        {
            "policy_input": {"classification": {"artifact_digest": m["digest"]}},
            "detector_evidence_version": "1",
            "detector_snapshot": {"sha256": m["digest"], "schema_version": 1},
            "transformation": {"applied": True, "verification": {"artifact_digest": "f" * 64}},
        },
    )
    with pytest.raises(DetectorEvidenceError):
        verify_detector_references(str(audit.db_path), str(tmp_path / "detectors"))


def test_export_verify_package_offline_without_raw_prompt(tmp_path, audit):
    m = detector_manifest()
    d = tmp_path / "detectors"
    archive_manifest(m, d)
    commit_m5(audit, m["digest"])
    output = tmp_path / "evidence.zip"
    public = str(audit.key_path.with_suffix(".pub.pem"))
    exported = export_package(
        str(audit.db_path), public, str(tmp_path / "unused-policies"), str(d), str(output)
    )
    assert exported["detector_manifests"] == 1
    report = verify_package(str(output), evaluator=lambda *_: {})
    assert report["status"] == "EVIDENCE_PACKAGE_SELF_CONSISTENT"
    assert report["audit"]["detector_provenance_verified"] == 1
    assert not report["checkpoint_trusted_externally"]
    with zipfile.ZipFile(output) as bundle:
        assert "audit-key.pem" not in bundle.namelist()
        assert "detector-archive/" + m["digest"] + ".json" in bundle.namelist()
        assert all("private-key" not in name for name in bundle.namelist())


def test_modified_zip_is_detected_before_audit_replay(tmp_path, audit):
    m = detector_manifest()
    d = tmp_path / "detectors"
    archive_manifest(m, d)
    commit_m5(audit, m["digest"])
    output = tmp_path / "evidence.zip"
    export_package(
        str(audit.db_path),
        str(audit.key_path.with_suffix(".pub.pem")),
        str(tmp_path / "unused-policies"),
        str(d),
        str(output),
    )
    damaged = tmp_path / "damaged.zip"
    with zipfile.ZipFile(output) as original, zipfile.ZipFile(damaged, "w") as modified:
        for item in original.infolist():
            raw = original.read(item.filename)
            if item.filename.endswith("audit-key.pub.pem"):
                raw += b"tampered"
            modified.writestr(item.filename, raw)
    with pytest.raises(EvidencePackageError):
        verify_package(str(damaged), evaluator=lambda *_: {})


def test_zip_path_traversal_is_rejected(tmp_path):
    output = tmp_path / "malicious.zip"
    with zipfile.ZipFile(output, "w") as bundle:
        bundle.writestr("../outside", "no")
        bundle.writestr("package-manifest.json", "{}")
    with pytest.raises(EvidencePackageError):
        verify_package(str(output), evaluator=lambda *_: {})


def test_external_public_key_enables_authentication(tmp_path, audit):
    m = detector_manifest()
    d = tmp_path / "detectors"
    archive_manifest(m, d)
    commit_m5(audit, m["digest"])
    output = tmp_path / "package.zip"
    public = str(audit.key_path.with_suffix(".pub.pem"))
    export_package(str(audit.db_path), public, str(tmp_path / "none"), str(d), str(output))
    report = verify_package(str(output), evaluator=lambda *_: {}, trusted_public_key=public)
    assert report["status"] == "EVIDENCE_PACKAGE_VERIFIED"
    assert report["public_key_trusted_externally"]
    wrong = tmp_path / "other.pem"
    wrong.write_text("-----BEGIN PUBLIC KEY-----\nwrong\n-----END PUBLIC KEY-----")
    with pytest.raises(EvidencePackageError):
        verify_package(str(output), evaluator=lambda *_: {}, trusted_public_key=str(wrong))


def test_exported_package_contains_replayable_rego_and_detector_provenance(tmp_path, audit):
    from app.domain.contracts import Effect, Obligation, PolicyDecision
    from app.policy.snapshots import build_snapshot
    from tests.test_policy_snapshots import SOURCE

    src = tmp_path / "editable"
    src.mkdir()
    (src / "decision.rego").write_text(SOURCE, encoding="utf-8")
    archive = tmp_path / "policy-archive"
    info = build_snapshot(src, archive, tmp_path / "active")
    m = detector_manifest()
    d = tmp_path / "detectors"
    archive_manifest(m, d)
    policy_decision = PolicyDecision(
        Effect.PERMIT,
        (Obligation("ROUTE", "sovereign-model"),),
        ("TEST_PERMIT",),
        info.policy_revision,
        info.policy_digest,
    )
    audit.commit(
        "req",
        "tenant",
        "DECISION",
        {
            "policy_input": {"classification": {"artifact_digest": m["digest"]}},
            "policy_snapshot": {"sha256": info.policy_digest, "revision": info.policy_revision},
            "policy_evaluation": policy_decision.to_dict(),
            "decision": policy_decision.to_dict(),
            "detector_evidence_version": "1",
            "detector_snapshot": {"sha256": m["digest"], "schema_version": 1},
        },
    )
    output = tmp_path / "result.zip"
    public = str(audit.key_path.with_suffix(".pub.pem"))
    exported = export_package(str(audit.db_path), public, str(archive), str(d), str(output))
    assert exported["policy_snapshots"] == 1
    with zipfile.ZipFile(output) as zip_file:
        assert f"policy-archive/{info.policy_digest}/decision.rego" in zip_file.namelist()
    verified = verify_package(
        str(output), evaluator=lambda *_: policy_decision.to_dict(), trusted_public_key=public
    )
    assert verified["audit"]["policy_decisions_replayed"] == 1
    assert verified["audit"]["detector_provenance_verified"] == 1


def test_external_witnessed_checkpoint_rejects_truncation(tmp_path, audit):
    m = detector_manifest()
    d = tmp_path / "detectors"
    archive_manifest(m, d)
    commit_m5(audit, m["digest"])
    output = tmp_path / "snapshot.zip"
    public = str(audit.key_path.with_suffix(".pub.pem"))
    export_package(str(audit.db_path), public, str(tmp_path / "none"), str(d), str(output))
    external_checkpoint = tmp_path / "independent-checkpoint.json"
    with zipfile.ZipFile(output) as zip_file:
        external_checkpoint.write_bytes(zip_file.read("checkpoint.json"))
    verified = verify_package(
        str(output),
        evaluator=lambda *_: {},
        trusted_public_key=public,
        trusted_checkpoint=str(external_checkpoint),
    )
    assert verified["checkpoint_trusted_externally"]
    external_checkpoint.write_text(json.dumps({"latest_sequence": 0}))
    with pytest.raises(Exception):
        verify_package(
            str(output),
            evaluator=lambda *_: {},
            trusted_public_key=public,
            trusted_checkpoint=str(external_checkpoint),
        )


def test_manifest_streams_hash_and_refuses_excess_bytes(tmp_path):
    """The manifest hashes larger files without a per-file read_bytes() allocation."""
    sample = tmp_path / "audit.sqlite"
    sample.write_bytes(b"synthetic" * 256)
    expected = hashlib.sha256(sample.read_bytes()).hexdigest()
    with pytest.raises(EvidencePackageError, match="size limit"):
        _manifest_of(tmp_path, max_uncompressed_bytes=128)
    manifest = _manifest_of(tmp_path, max_uncompressed_bytes=4096)
    assert manifest["files"] == [
        {"path": "audit.sqlite", "sha256": expected, "size": sample.stat().st_size}
    ]


@pytest.mark.parametrize("limit", (0, -1, 1025, True, 3.5, "512"))
def test_evidence_limit_rejects_invalid_overrides(limit):
    from app.audit.evidence_package import _uncompressed_limit

    with pytest.raises(EvidencePackageError, match="1 to 1024"):
        _uncompressed_limit(limit)


def test_explicit_large_evidence_limit_applies_to_export_and_review(tmp_path, audit):
    """Large SQLite input requires matching, explicit export/reviewer limits."""
    with closing(sqlite3.connect(audit.db_path)) as conn, conn:
        conn.execute("CREATE TABLE synthetic_padding (bytes BLOB NOT NULL)")
        conn.execute("INSERT INTO synthetic_padding VALUES (zeroblob(2097152))")
        conn.commit()

    bundle = tmp_path / "large-evidence.zip"
    public = str(audit.key_path.with_suffix(".pub.pem"))
    with pytest.raises(EvidencePackageError, match="size limit"):
        export_package(
            str(audit.db_path),
            public,
            str(tmp_path / "unused-policy"),
            str(tmp_path / "unused-detectors"),
            str(bundle),
            max_uncompressed_mib=1,
        )
    assert not bundle.exists()

    exported = export_package(
        str(audit.db_path),
        public,
        str(tmp_path / "unused-policy"),
        str(tmp_path / "unused-detectors"),
        str(bundle),
        max_uncompressed_mib=8,
    )
    assert exported["status"] == "EXPORTED"
    with pytest.raises(EvidencePackageError, match="size limit"):
        verify_package(str(bundle), max_uncompressed_mib=1)

    verified = verify_package(str(bundle), max_uncompressed_mib=8)
    assert verified["status"] == "EVIDENCE_PACKAGE_SELF_CONSISTENT"
    assert verified["audit"]["verified_events"] == 0
