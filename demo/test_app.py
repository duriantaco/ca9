"""Tests for the Acme weather dashboard."""

from unittest.mock import MagicMock, patch

import pytest
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_index(client):
    resp = client.get("/")
    data = resp.get_json()
    assert resp.status_code == 200
    assert data["service"] == "acme-weather"
    assert "version" in data


def test_health(client):
    resp = client.get("/health")
    data = resp.get_json()
    assert resp.status_code == 200
    assert data["healthy"] is True


@patch("app.requests.get")
def test_weather_default_city(mock_get, client):
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "current_condition": [
            {
                "temp_C": "28",
                "weatherDesc": [{"value": "Partly cloudy"}],
            }
        ]
    }
    mock_resp.raise_for_status = MagicMock()
    mock_get.return_value = mock_resp

    resp = client.get("/weather")
    data = resp.get_json()
    assert resp.status_code == 200
    assert data["city"] == "Singapore"
    assert data["temp_c"] == "28"
    assert data["description"] == "Partly cloudy"


@patch("app.requests.get")
def test_weather_custom_city(mock_get, client):
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "current_condition": [
            {
                "temp_C": "15",
                "weatherDesc": [{"value": "Rainy"}],
            }
        ]
    }
    mock_resp.raise_for_status = MagicMock()
    mock_get.return_value = mock_resp

    resp = client.get("/weather?city=Tokyo")
    data = resp.get_json()
    assert data["city"] == "Tokyo"
    assert data["temp_c"] == "15"


@patch("app.requests.get")
def test_weather_api_error(mock_get, client):
    mock_get.side_effect = ConnectionError("Connection timeout")
    with pytest.raises(ConnectionError):
        client.get("/weather")
