# Copyright 2018 Google LLC and 2022 Matthieu Berthomé
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
import glob
import os
import site
import sys
import requests

from invoke import task

from magicproxy.config import load_config, DEFAULT_PUBLIC_ACCESS
from magicproxy.crypto import generate_keys as gen_keys


@task
def create_token(c):
    config = load_config()

    url = (
        config.PUBLIC_ACCESS
        if config.PUBLIC_ACCESS
        else input("Enter the URL for your proxy (https://example.com): ")
    )
    token = input("Enter your API Token: ")
    permissions = input("Enter a comma-separate list of permissions: ")

    url += "/__magictoken"
    permissions = [x.strip() for x in permissions.split(",") if x != ""]

    request_data = {"token": token, "permissions": permissions}

    resp = requests.post(url, json=request_data)
    resp.raise_for_status()

    print(resp.text)


@task
def generate_keys(c, url=None):
    if url is None:
        url = input(f"Enter the URL for your proxy (default {DEFAULT_PUBLIC_ACCESS}): ")
        if len(url) == 0:
            url = DEFAULT_PUBLIC_ACCESS
    config = load_config(_load_keys=False, public_access=url)
    config.public_access = url
    gen_keys(config)


@task
def blacken(c):
    c.run("black src/magicproxy tests setup.py tasks.py")


@task
def lint(c):
    c.run("flake8 src/magicproxy tests")
    c.run("mypy --no-strict-optional --ignore-missing-imports src/magicproxy")


COV_LINE = "import coverage; coverage.process_startup()"


@task
def test(c):
    c.run("pip install -e .")
    args = tuple()
    if "--" in sys.argv:
        args = sys.argv[sys.argv.index("--") + 1 :]

    c.run("pytest tests " + " ".join(args))


@task
def test_coverage(c):
    c.run("pip install -e .")
    args = tuple()
    if "--" in sys.argv:
        args = sys.argv[sys.argv.index("--") + 1 :]

    c.run("coverage erase")
    c.run("coverage run --source src -m pytest tests " + " ".join(args))
    os.chdir("src")
    datafile = "--data-file=../.coverage"
    c.run(f"coverage combine {datafile}")
    c.run(f"coverage report {datafile}")
    c.run(f"coverage json {datafile} -o ../coverage.json")
    c.run(f"coverage xml {datafile} -o ../coverage.xml")
