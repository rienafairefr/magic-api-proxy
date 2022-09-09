import multiprocessing
import os
import shlex
import subprocess
import sys
import time
from random import randrange
from socket import create_connection

import flask
import pytest
import requests

import magicproxy
from magicproxy import async_proxy, proxy
from magicproxy.config import load_config
from multiprocessing import Process

API_PORT = randrange(50000, 55000)
API_HOST = "localhost"
API_ROOT = f"http://{API_HOST}:{API_PORT}"
PROXY_PORT = randrange(55000, 60000)
PROXY_HOST = "localhost"
PROXY_ROOT = f"http://{PROXY_HOST}:{PROXY_PORT}"
TIMEOUT = 15

config = load_config()

print("API_PORT %s" % API_PORT)
print("PROXY_PORT %s" % PROXY_PORT)


def run(cmd):
    print(" ".join(shlex.quote(s) for s in cmd))
    return (
        subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        .decode("utf-8")
        .rstrip("\n")
    )


def wait_for_port(host: str, port: int, timeout: float = 5.0):
    start_time = time.perf_counter()
    while True:
        try:
            with create_connection((host, port), timeout=timeout):
                time.sleep(2)
                break
        except Exception as ex:
            time.sleep(0.01)
            if time.perf_counter() - start_time >= timeout:
                raise TimeoutError(
                    "Waited too long for the port {} on host {} to start accepting "
                    "connections.".format(port, host)
                ) from ex


@pytest.fixture(scope="module")
def api_integration():
    app = flask.Flask("api")

    @app.route("/", methods=["GET"])
    def route():
        authorization_header = flask.request.headers.get("authorization")

        if authorization_header:
            if authorization_header.startswith("Bearer "):
                if authorization_header[len("Bearer "):] == "fake_token":
                    return "authorized by API", 200

        return "not authorized by API", 401

    def api_target():
        app.run(host=API_HOST, port=API_PORT)

    api_process = Process(target=api_target)
    api_process.start()
    wait_for_port(API_HOST, API_PORT, 10)
    yield
    api_process.terminate()
    api_process.join()


@pytest.fixture(scope="module")
def integration(api_integration, request):
    run_async = request.param
    run_args = [sys.executable]
    if "COVERAGE_RUN" in os.environ:
        root_dir = os.path.join(os.path.dirname(__file__), "..")
        rcfile = os.path.join(root_dir, ".coveragerc")
        covfile = os.path.join(root_dir, ".coverage")
        omitted = os.path.join(root_dir, "tests/*")
        srcdir = os.path.join(root_dir, "src")
        run_args.extend(
            [
                "-m",
                "coverage",
                "run",
                f"--source={srcdir}",
                f"--rcfile={rcfile}",
                f"--data-file={covfile}",
                "-p",
                f"--omit={omitted}",
            ]
        )

    def proxy_target():
        os.environ.update({
            "API_ROOT": API_ROOT,
            "PYTHONUNBUFFERED": "1",
            "PUBLIC_ACCESS": PROXY_ROOT,
            "PUBLIC_KEY_LOCATION": os.path.abspath(config.public_key_location),
            "PRIVATE_KEY_LOCATION": os.path.abspath(config.private_key_location),
            "PUBLIC_CERTIFICATE_LOCATION": os.path.abspath(
                config.public_certificate_location
            ),
        })
        module = async_proxy if run_async else proxy
        module.run_app(host=PROXY_HOST, port=PROXY_PORT)

    proxy_process = multiprocessing.Process(target=proxy_target)
    proxy_process.start()
    wait_for_port(PROXY_HOST, PROXY_PORT, 10)
    yield
    proxy_process.terminate()
    proxy_process.join()


async_or_not = (False, )
async_or_not_ids = ["run_async" if r else "sync" for r in async_or_not]


@pytest.mark.integration
@pytest.mark.parametrize(
    "integration", async_or_not, ids=async_or_not_ids, indirect=True
)
def test_api_get___magictoken(integration):
    response = requests.get(f"{PROXY_ROOT}/__magictoken")
    assert response.ok
    assert response.status_code == 200

    assert magicproxy.__version__ in response.text
    assert API_ROOT in response.text


@pytest.mark.integration
@pytest.mark.parametrize(
    "integration", async_or_not, ids=async_or_not_ids, indirect=True
)
def test_extra_keys(integration):
    response = requests.post(
        f"{PROXY_ROOT}/__magictoken",
        json={"allowed": ["GET /.*"], "token_": "fake_token"},
    )
    assert not response.ok
    assert response.status_code == 400

    response = requests.post(
        f"{PROXY_ROOT}/__magictoken",
        json={"allowed_": ["GET /.*"], "token": "fake_token"},
    )
    assert not response.ok
    assert response.status_code == 400


@pytest.mark.integration
@pytest.mark.parametrize(
    "integration", async_or_not, ids=async_or_not_ids, indirect=True
)
def test_api_authorized(integration):
    response = requests.post(
        f"{PROXY_ROOT}/__magictoken",
        json={"allowed": ["GET /.*"], "token": "fake_token"},
    )
    assert response.ok
    assert response.status_code == 200

    proxy_token = response.text

    response = requests.get(
        PROXY_ROOT,
        headers={"Authorization": f"Bearer {proxy_token}"},
    )
    assert response.ok
    assert response.status_code == 200
    assert response.text == "authorized by API"


@pytest.mark.integration
@pytest.mark.parametrize(
    "integration", async_or_not, ids=async_or_not_ids, indirect=True
)
def test_api_unauthorized(integration):
    response = requests.post(
        f"{PROXY_ROOT}/__magictoken",
        json={"allowed": ["GET /.*"], "token": "wrong_token"},
    )
    assert response.ok
    assert response.status_code == 200

    proxy_token = response.text

    response = requests.get(
        f"{PROXY_ROOT}/",
        headers={"Authorization": f"Bearer {proxy_token}"},
    )
    assert not response.ok
    assert response.status_code == 401
    assert response.text == "not authorized by API"
