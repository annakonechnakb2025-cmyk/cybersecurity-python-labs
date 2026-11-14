import json
from pathlib import Path

import pytest
import requests

from labs.lab04.api_client import build_headers, fetch_response

CVE_ID = "CVE-2099-10001"

SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"


def test_build_headers_without_api_key(monkeypatch):
    """Перевіряє заголовки без API-ключа."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)

    headers = build_headers()

    assert headers == {"Accept": "application/json"}


def test_build_headers_with_api_key(monkeypatch):
    """Перевіряє заголовки з API-ключем."""
    monkeypatch.setenv("NVD_API_KEY", "test-api-key")

    headers = build_headers()

    assert headers["Accept"] == "application/json"
    assert headers["apiKey"] == "test-api-key"


def test_fetch_response(monkeypatch):
    """Перевіряє успішний HTTP-запит без інтернету."""
    with SAMPLE_PATH.open(encoding="utf-8") as file:
        expected_payload = json.load(file)

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return expected_payload

    def fake_get(url, **kwargs):
        assert url == ("https://services.nvd.nist.gov/rest/json/cves/2.0")
        assert kwargs["params"] == {"cveId": CVE_ID}
        assert kwargs["headers"]["Accept"] == "application/json"
        assert kwargs["timeout"] == (3.05, 10)
        assert kwargs["allow_redirects"] is False

        return FakeResponse()

    monkeypatch.setattr(
        "labs.lab04.api_client.requests.get",
        fake_get,
    )

    result = fetch_response(CVE_ID)

    assert result == expected_payload


def test_fetch_response_http_error(monkeypatch):
    """Перевіряє HTTP-помилку 500 без інтернету."""

    class FakeResponse:
        status_code = 500

        def raise_for_status(self):
            raise requests.HTTPError("500 Server Error")

    def fake_get(url, **kwargs):
        return FakeResponse()

    monkeypatch.setattr(
        "labs.lab04.api_client.requests.get",
        fake_get,
    )

    with pytest.raises(requests.HTTPError):
        fetch_response(CVE_ID)
