import pytest


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    """Ізолює тести від реальної мережі та API-ключа."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request")
