import colorama
import requests
import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)

try:
    with open("config.yaml") as f:
        CONFIG = yaml.safe_load(f)
except FileNotFoundError:
    CONFIG = {"api_base": "https://wttr.in", "default_city": "Singapore"}

colorama.init()

WEATHER_API = CONFIG.get("api_base", "https://wttr.in")


@app.route("/")
def index():
    return jsonify({"service": "acme-weather", "version": "1.0.0"})


@app.route("/weather")
def weather():
    city = request.args.get("city", CONFIG.get("default_city", "London"))
    resp = requests.get(f"{WEATHER_API}/{city}?format=j1", timeout=5)
    resp.raise_for_status()
    data = resp.json()
    return jsonify(
        {
            "city": city,
            "temp_c": data.get("current_condition", [{}])[0].get("temp_C"),
            "description": data.get("current_condition", [{}])[0]
            .get("weatherDesc", [{}])[0]
            .get("value"),
        }
    )


@app.route("/health")
def health():
    return jsonify({"healthy": True})


if __name__ == "__main__":
    app.run(debug=True, port=5050)
