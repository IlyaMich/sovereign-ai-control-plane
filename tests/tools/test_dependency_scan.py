"""A successful scanner invocation must actually include Python dependencies."""

import pytest

from tools.verify_dependency_scan import verify_report


@pytest.mark.parametrize(
    "report",
    [
        {},
        {"Results": []},
        {"Results": [{"Type": "dockerfile", "Target": "deploy/Containerfile"}]},
        {"Results": [{"Type": "pip", "Target": "unrelated.txt"}]},
    ],
)
def test_missing_dependency_coverage_is_rejected(report):
    with pytest.raises(ValueError, match="dependency coverage is missing"):
        verify_report(report)


def test_clean_requirements_scan_is_accepted():
    verify_report({"Results": [{"Type": "pip", "Target": "requirements.txt"}]})
