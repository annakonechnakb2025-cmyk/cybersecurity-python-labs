import copy
import json
from pathlib import Path

import pytest

from labs.lab04.analysis import build_report, extract_record

CVE_ID = "CVE-2099-10001"
VARIANT = 13

SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"


@pytest.fixture
def sample_payload():
    """Завантажує тестову відповідь NVD."""
    with SAMPLE_PATH.open(encoding="utf-8") as file:
        return json.load(file)


def get_cvss_data(payload):
    """Повертає CVSS-дані першої оцінки."""
    return payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0][
        "cvssData"
    ]


def make_report(payload):
    """Створює звіт для варіанта 13."""
    record = extract_record(payload, CVE_ID)
    return build_report(record, CVE_ID, VARIANT)


@pytest.mark.parametrize(
    "score, impact, expected_decision",
    [
        (5.9, "LOW", "other"),
        (6.0, "LOW", "review"),
        (7.5, "LOW", "review"),
        (9.8, "HIGH", "other"),
    ],
)
def test_variant_13_rule(sample_payload, score, impact, expected_decision):
    """Перевіряє правило варіанта 13."""
    payload = copy.deepcopy(sample_payload)
    cvss_data = get_cvss_data(payload)

    cvss_data["baseScore"] = score
    cvss_data["integrityImpact"] = impact

    report = make_report(payload)

    assert report["decision"] == expected_decision
    assert report["score"] == score
    assert report["observed"] == impact
    assert report["variant"] == VARIANT
    assert report["rule"] == {
        "threshold": 6.0,
        "field": "integrityImpact",
        "expected": "LOW",
    }


def test_cve_not_found():
    """Перевіряє відсутність CVE."""
    payload = {"vulnerabilities": []}

    record = extract_record(payload, CVE_ID)
    report = build_report(record, CVE_ID, VARIANT)

    assert record is None
    assert report["decision"] == "not_found"
    assert report["score"] is None
    assert report["observed"] is None
    assert report["description"] is None


def test_rejected_cve(sample_payload):
    """Перевіряє відхилену вразливість."""
    payload = copy.deepcopy(sample_payload)

    payload["vulnerabilities"][0]["cve"]["vulnStatus"] = "Rejected"

    report = make_report(payload)

    assert report["decision"] == "rejected"
    assert report["score"] is None
    assert report["observed"] is None
    assert report["vuln_status"] == "Rejected"


def test_missing_status(sample_payload):
    """Перевіряє відсутність статусу."""
    payload = copy.deepcopy(sample_payload)

    del payload["vulnerabilities"][0]["cve"]["vulnStatus"]

    report = make_report(payload)

    assert report["decision"] == "insufficient_data"
    assert report["score"] is None
    assert report["observed"] is None


def test_missing_cvss_metrics(sample_payload):
    """Перевіряє відсутність CVSS-метрик."""
    payload = copy.deepcopy(sample_payload)

    del payload["vulnerabilities"][0]["cve"]["metrics"]

    report = make_report(payload)

    assert report["decision"] == "insufficient_data"
    assert report["score"] is None
    assert report["observed"] is None


def test_missing_integrity_impact(sample_payload):
    """Перевіряє відсутність поля варіанта."""
    payload = copy.deepcopy(sample_payload)

    del get_cvss_data(payload)["integrityImpact"]

    report = make_report(payload)

    assert report["decision"] == "insufficient_data"
    assert report["observed"] is None


def test_invalid_cvss_score(sample_payload):
    """Перевіряє оцінку CVSS поза діапазоном."""
    payload = copy.deepcopy(sample_payload)

    get_cvss_data(payload)["baseScore"] = 15.0

    with pytest.raises(ValueError, match="Invalid CVSS baseScore"):
        extract_record(payload, CVE_ID)


def test_invalid_cvss_score_type(sample_payload):
    """Перевіряє неправильний тип оцінки."""
    payload = copy.deepcopy(sample_payload)

    get_cvss_data(payload)["baseScore"] = "9.8"

    with pytest.raises((TypeError, ValueError)):
        extract_record(payload, CVE_ID)


def test_invalid_integrity_impact(sample_payload):
    """Перевіряє недопустиме значення поля варіанта."""
    payload = copy.deepcopy(sample_payload)

    get_cvss_data(payload)["integrityImpact"] = "INVALID"

    with pytest.raises((TypeError, ValueError)):
        make_report(payload)


def test_null_integrity_impact(sample_payload):
    """Перевіряє null замість допустимого значення."""
    payload = copy.deepcopy(sample_payload)

    get_cvss_data(payload)["integrityImpact"] = None

    with pytest.raises((TypeError, ValueError)):
        make_report(payload)


def test_invalid_payload_type():
    """Перевіряє неправильний тип відповіді NVD."""
    with pytest.raises(TypeError):
        extract_record([], CVE_ID)


def test_primary_cvss_has_priority(sample_payload):
    """Primary має пріоритет над попередньою Secondary."""
    payload = copy.deepcopy(sample_payload)

    metrics = payload["vulnerabilities"][0]["cve"]["metrics"]
    original = metrics["cvssMetricV31"][0]

    secondary = copy.deepcopy(original)
    secondary["type"] = "Secondary"
    secondary["cvssData"]["baseScore"] = 8.0
    secondary["cvssData"]["integrityImpact"] = "HIGH"

    primary = copy.deepcopy(original)
    primary["type"] = "Primary"
    primary["cvssData"]["baseScore"] = 6.5
    primary["cvssData"]["integrityImpact"] = "LOW"

    metrics["cvssMetricV31"] = [secondary, primary]

    report = make_report(payload)

    assert report["score"] == 6.5
    assert report["observed"] == "LOW"
    assert report["decision"] == "review"


def test_first_cvss_when_primary_missing(sample_payload):
    """Без Primary вибирається перша оцінка."""
    payload = copy.deepcopy(sample_payload)

    metrics = payload["vulnerabilities"][0]["cve"]["metrics"]
    original = metrics["cvssMetricV31"][0]

    first = copy.deepcopy(original)
    first["type"] = "Secondary"
    first["cvssData"]["baseScore"] = 7.0
    first["cvssData"]["integrityImpact"] = "LOW"

    second = copy.deepcopy(original)
    second["type"] = "Secondary"
    second["cvssData"]["baseScore"] = 9.0
    second["cvssData"]["integrityImpact"] = "HIGH"

    metrics["cvssMetricV31"] = [first, second]

    report = make_report(payload)

    assert report["score"] == 7.0
    assert report["observed"] == "LOW"
    assert report["decision"] == "review"
