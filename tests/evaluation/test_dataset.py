"""Stage 1 ground-truth integrity and dataset reproducibility."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from evaluation.dataset import DEFAULT_DATASET, DatasetError, load_dataset
from evaluation.generate_dataset import generate, write_dataset


def test_dataset_1200_cases_and_expected_splits():
    dataset = load_dataset()
    assert len(dataset.cases) == 1200
    assert len(dataset.select("development")) == 240
    assert len(dataset.select("validation")) == 240
    assert len(dataset.select("evaluation")) == 720
    assert Counter(c.group for c in dataset.cases) == dataset.manifest["distribution"]
    assert all(c.expected_status == "UNKNOWN" for c in dataset.cases if not c.in_scope)
    assert any(c.entities for c in dataset.cases if c.in_scope)
    assert len({c.id for c in dataset.cases}) == 1200


def test_generated_fixture_is_byte_identical(tmp_path: Path):
    write_dataset(tmp_path)
    for name in ("cases.jsonl", "manifest.json"):
        assert (tmp_path / name).read_bytes() == (DEFAULT_DATASET / name).read_bytes()
    assert [c["id"] for c in generate()] == [c.id for c in load_dataset().cases]


def test_modified_labels_fail_before_evaluation(tmp_path: Path):
    write_dataset(tmp_path)
    file = tmp_path / "cases.jsonl"
    file.write_bytes(file.read_bytes().replace(b"EMAIL_ADDRESS", b"PERSON", 1))
    with pytest.raises(DatasetError, match="checksum"):
        load_dataset(tmp_path)


def test_invalid_spans_rejected_even_with_recomputed_manifest(tmp_path: Path):
    import hashlib

    write_dataset(tmp_path)
    file = tmp_path / "cases.jsonl"
    contents = file.read_text(encoding="utf-8").splitlines()
    first = json.loads(contents[0])
    first["expected_entities"][0]["end"] = len(first["text"]) + 500
    contents[0] = json.dumps(first, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    data = ("\n".join(contents) + "\n").encode("utf-8")
    file.write_bytes(data)
    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["cases_sha256"] = hashlib.sha256(data).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(DatasetError):
        load_dataset(tmp_path)


def test_crlf_conversion_reports_actionable_error(tmp_path: Path):
    write_dataset(tmp_path)
    file = tmp_path / "cases.jsonl"
    data = file.read_bytes()
    file.write_bytes(data.replace(b"\n", b"\r\n"))
    with pytest.raises(DatasetError, match="Windows CRLF line endings"):
        load_dataset(tmp_path)
    write_dataset(tmp_path)
    assert len(load_dataset(tmp_path).cases) == 1200
