# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging
import os
import traceback
from typing import Tuple, Set

import flask
import requests

import magicproxy
import magicproxy.types
from . import magictoken
from . import queries
from . import scopes
from .config import Config, load_config
from .headers import clean_request_headers, clean_response_headers
from .magictoken import magictoken_params_validate

logger = logging.getLogger(__name__)

app = flask.Flask(__name__)

query_params_to_clean: Set[str] = set()

custom_request_headers_to_clean: Set[str] = set()


@app.route("/__magictoken", methods=["POST", "GET"])
def create_magic_token():
    config: Config = app.config["CONFIG"]
    if config is None:
        return "magic API proxy version " + magicproxy.__version__, 503
    api_root = config.api_root
    if flask.request.method == "GET":
        return "magic API proxy for " + api_root + " version " + magicproxy.__version__
    params = flask.request.json
    try:
        magictoken_params_validate(config, params)
    except ValueError as e:
        return str(e), 400

    token = magictoken.create(config.keys, params["token"], params.get("scopes"), params.get("allowed"))
    return token, 200, {"Content-Type": "application/jwt"}


def _proxy_request(request: flask.Request, url: str, headers=None, **kwargs) -> Tuple[bytes, int, dict]:
    clean_headers = clean_request_headers(request.headers, custom_request_headers_to_clean)

    if headers:
        clean_headers.update(headers)

    logger.debug(
        f"Proxying to {request.method} {url}\nHeaders: {clean_headers}\nQuery: {request.args}\nContent: {request.data!r}"
    )

    # Make the API request
    resp = requests.request(
        url=url,
        method=request.method,
        headers=clean_headers,
        params=dict(request.args),
        data=request.data,
        **kwargs,
    )

    response_headers = clean_response_headers(resp.headers)

    logger.debug(resp, resp.headers, resp.content)

    return resp.content, resp.status_code, response_headers


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>", methods=["POST", "GET", "PATCH", "PUT", "DELETE"])
def proxy_api(path):
    config = app.config["CONFIG"]
    if config is None:
        return "magic API proxy version " + magicproxy.__version__, 503
    auth_token = flask.request.headers.get("Authorization")
    if auth_token is None:
        return "No authorization token presented", 401
    # strip out "Bearer " if needed
    if auth_token.startswith("Bearer "):
        auth_token = auth_token[len("Bearer ") :]

    try:
        # Validate the magic token
        token_info = magictoken.decode(config.keys, auth_token)
    except ValueError:
        return "Not a valid magic token", 400

    # Validate scopes against URL and method.
    if not scopes.validate_request(config, flask.request.method, path, token_info.scopes, token_info.allowed):
        return (
            "Disallowed by API proxy",
            401,
        )

    path = queries.clean_path_queries(query_params_to_clean, path)

    response = _proxy_request(
        request=flask.request,
        url=f"{config.api_root}/{path}",
        headers={"Authorization": f"Bearer {token_info.token}"},
    )

    try:
        scopes.response_callback(config, flask.request.method, path, *response, token_info.scopes)
    except Exception as e:
        logger.error("exception in response_callback")
        logger.error(e)
        logger.error(traceback.format_exc())

    return response


def build_app(config: Config = None):
    if "COVERAGE_RUN" in os.environ:
        import coverage

        coverage.process_startup()
    if config is None:
        try:
            config = load_config()
        except RuntimeError:
            # will run, but in degraded mode (503)
            pass
    app.config["CONFIG"] = config
    return app


def run_app(host, port, config: Config = None):
    build_app(config).run(
        host=host,
        port=port,
        use_reloader=os.environ.get("FLASK_USE_RELOADER") is not None,
    )
