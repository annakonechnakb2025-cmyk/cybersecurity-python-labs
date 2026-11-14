import math


def extract_record(payload: dict, cve_id: str) -> dict | None:
    """
    Перевіряє відповідь NVD API та повертає внутрішній запис.

    Внутрішній запис містить опис, статус, оцінку CVSS,
    джерело оцінки, вектор і словник cvss_data.
    Якщо CVE не знайдено, повертає None.
    """
    if not isinstance(payload, dict):
        raise TypeError("NVD response must be an object")

    vulnerabilities = payload.get("vulnerabilities")

    if not isinstance(vulnerabilities, list):
        raise TypeError("vulnerabilities must be a list")

    if len(vulnerabilities) > 1:
        raise ValueError("Expected at most one vulnerability")

    if not vulnerabilities:
        return None

    item = vulnerabilities[0]

    if not isinstance(item, dict):
        raise TypeError("Invalid vulnerability entry")

    cve = item.get("cve")

    if not isinstance(cve, dict):
        raise TypeError("Missing or invalid cve object")

    if cve.get("id") != cve_id:
        raise ValueError("CVE identifier mismatch")

    status = cve.get("vulnStatus")

    if status is not None and (not isinstance(status, str) or not status.strip()):
        raise ValueError("Invalid vulnerability status")

    description = None

    if "descriptions" in cve:
        descriptions = cve["descriptions"]

        if not isinstance(descriptions, list):
            raise ValueError("Invalid descriptions")

        for entry in descriptions:
            if not isinstance(entry, dict):
                raise TypeError("Invalid description entry")

            if not isinstance(entry.get("lang"), str):
                raise TypeError("Invalid description language")

            if not isinstance(entry.get("value"), str):
                raise TypeError("Invalid description value")

            if description is None and entry["lang"] == "en" and entry["value"].strip():
                description = entry["value"]

    record = {
        "description": description,
        "vuln_status": status,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "cvss_data": None,
    }

    if status is None or status == "Rejected":
        return record

    if "metrics" not in cve:
        return record

    metrics = cve["metrics"]

    if not isinstance(metrics, dict):
        raise TypeError("Invalid metrics")

    if "cvssMetricV31" not in metrics:
        return record

    entries = metrics["cvssMetricV31"]

    if not isinstance(entries, list):
        raise TypeError("Invalid CVSS v3.1 metrics")

    if not entries:
        return record

    if not all(isinstance(entry, dict) for entry in entries):
        raise ValueError("Invalid CVSS metric entry")

    selected = next(
        (entry for entry in entries if entry.get("type") == "Primary"),
        entries[0],
    )

    cvss_data = selected.get("cvssData")

    if not isinstance(cvss_data, dict):
        raise TypeError("Invalid cvssData")

    score = cvss_data.get("baseScore")

    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(score)
        or not 0 <= score <= 10
    ):
        raise ValueError("Invalid CVSS baseScore")

    for field in ("version", "vectorString"):
        if field in cvss_data:
            value = cvss_data[field]

            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Invalid {field}")

    if "source" in selected:
        source = selected["source"]

        if not isinstance(source, str) or not source.strip():
            raise ValueError("Invalid score source")

    version = cvss_data.get("version")

    if version is not None and version != "3.1":
        raise ValueError("Expected CVSS version 3.1")

    record.update(
        {
            "cvss_version": version,
            "score": score,
            "score_source": selected.get("source"),
            "vector": cvss_data.get("vectorString"),
            "cvss_data": cvss_data.copy(),
        }
    )

    return record


def build_report(
    record: dict | None,
    cve_id: str,
    variant: int,
) -> dict:
    """Формує звіт і застосовує правило варіанта 13."""
    if type(variant) is not int or variant != 13:
        raise ValueError("Unsupported variant")

    rule = {
        "threshold": 6.0,
        "field": "integrityImpact",
        "expected": "LOW",
    }

    report = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": rule,
        "observed": None,
        "decision": "not_found",
    }

    if record is None:
        return report

    for key in (
        "description",
        "vuln_status",
        "cvss_version",
        "score",
        "score_source",
        "vector",
    ):
        report[key] = record[key]

    status = record["vuln_status"]

    if status == "Rejected":
        report["decision"] = "rejected"
        return report

    if status is None:
        report["decision"] = "insufficient_data"
        return report

    cvss_data = record["cvss_data"]

    if cvss_data is None:
        report["decision"] = "insufficient_data"
        return report

    field = rule["field"]

    if field not in cvss_data:
        report["decision"] = "insufficient_data"
        return report

    observed = cvss_data[field]

    if observed not in ("NONE", "LOW", "HIGH") or type(observed) is not str:
        raise ValueError("Invalid integrityImpact value")

    report["observed"] = observed

    if report["score"] >= rule["threshold"] and observed == rule["expected"]:
        report["decision"] = "review"
    else:
        report["decision"] = "other"

    return report
