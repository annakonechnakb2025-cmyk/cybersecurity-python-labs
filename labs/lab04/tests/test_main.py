import json
from pathlib import Path

import pytest

from labs.lab04 import main

CVE_ID = "CVE-2099-10001"

SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"


def test_local_mode(capsys, monkeypatch):
    """Перевіряє локальний запуск без HTTP-запитів."""

    def forbidden_fetch(cve_id):
        raise AssertionError("Network request is not allowed")

    monkeypatch.setattr(main, "fetch_response", forbidden_fetch)

    exit_code = main.main(
        [
            "--cve",
            CVE_ID,
            "--input",
            str(SAMPLE_PATH),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""

    report = json.loads(captured.out)

    assert report["cve_id"] == CVE_ID
    assert report["variant"] == 13
    assert report["score"] == 9.8
    assert report["observed"] == "HIGH"
    assert report["decision"] == "other"


def test_missing_file(capsys, tmp_path):
    """Перевіряє обробку відсутнього файла."""
    missing_file = tmp_path / "missing.json"

    exit_code = main.main(
        [
            "--cve",
            CVE_ID,
            "--input",
            str(missing_file),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "cannot read input file" in captured.err


def test_invalid_json(capsys, tmp_path):
    """Перевіряє обробку неправильного JSON."""
    invalid_file = tmp_path / "invalid.json"
    invalid_file.write_text("{invalid json", encoding="utf-8")

    exit_code = main.main(
        [
            "--cve",
            CVE_ID,
            "--input",
            str(invalid_file),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "invalid JSON" in captured.err


def test_invalid_cve(capsys):
    """Перевіряє неправильний формат CVE."""

    with pytest.raises(SystemExit) as error:
        main.main(["--cve", "INVALID-CVE"])

    assert error.value.code == 2
