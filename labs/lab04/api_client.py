import os

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def build_headers() -> dict[str, str]:
    """Формує заголовки для запиту до NVD API."""
    headers = {"Accept": "application/json"}

    api_key = os.getenv("NVD_API_KEY", "").strip()

    if api_key:
        headers["apiKey"] = api_key

    return headers


def fetch_response(cve_id: str) -> dict:
    """Отримує JSON-відповідь NVD API для заданого CVE."""
    response = requests.get(
        NVD_API_URL,
        params={"cveId": cve_id},
        headers=build_headers(),
        timeout=(3.05, 50),
        allow_redirects=False,
    )

    response.raise_for_status()

    if response.status_code != 200:
        raise ValueError(f"Unexpected HTTP status: {response.status_code}")

    return response.json()
