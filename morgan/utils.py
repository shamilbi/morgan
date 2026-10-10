from __future__ import annotations

import hashlib
import logging
import os
import re
import sys
from collections import OrderedDict
from typing import TYPE_CHECKING, Iterable

import dateutil  # type: ignore[import-untyped]
import requests

if TYPE_CHECKING:
    from datetime import datetime

    from packaging.requirements import Requirement

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0"
SESSION = requests.Session()


class MorganError(Exception):
    pass


class ParseError(MorganError):
    pass


def to_single_dash(filename):
    """https://packaging.python.org/en/latest/specifications/version-specifiers/#version-specifiers"""

    # selenium-2.0-dev-9429.tar.gz
    m = re.search(r"-[0-9].*-", filename)
    if m:
        s2 = filename[m.start() + 1 :]
        # 2.0-dev-9429.tar.gz
        s2 = s2.replace("-dev-", ".dev")
        # 2.0.dev9429.tar.gz
        s2 = s2.replace("-", ".")
        filename = filename[: m.start() + 1] + s2
    return filename
    # selenium-2.0.dev9429.tar.gz


def is_requirement_relevant(
    requirement: Requirement,
    envs: Iterable[dict],
    extras: set[str] | None = None,
) -> bool:
    """Determines if a requirement is relevant for any of the provided environments.

    Args:
        requirement: The requirement to evaluate.
        envs: The environments to check against.
        extras: Optional extras to consider during evaluation.

    Returns:
        True if the requirement has no marker or if its marker evaluates to
        True for at least one environment, False otherwise.
    """
    if not requirement.marker:
        return True

    # If no environments specified, assume relevant
    if not envs:
        return True

    for env in envs:
        # Create a copy of the environment to avoid modifying the original
        env_copy = env.copy()
        env_copy.setdefault("extra", "")
        if extras:
            env_copy["extra"] = ",".join(extras)

        if requirement.marker.evaluate(env_copy):
            return True

    return False


def filter_relevant_requirements(
    requirements: Iterable[Requirement],
    envs: Iterable[dict],
    extras: set[str] | None = None,
) -> set[Requirement]:
    """Filters a collection of requirements to only those relevant for the provided environments.

    Args:
        requirements: Requirements to filter.
        envs: The environments to check against.
        extras: Optional extras to consider during evaluation.

    Returns:
        Set of requirements relevant for at least one environment.
    """
    return {req for req in requirements if is_requirement_relevant(req, envs, extras)}


def touch_file(path: str, fileinfo: dict):
    """upload-time: 2025-05-28T18:46:29.349478Z"""
    time_str = fileinfo.get("upload-time")
    if not path or not time_str:
        return
    dt = dateutil.parser.parse(time_str)
    touch_file_dt(path, dt)


def touch_file_dt(path: str, dt: datetime):
    ts = dt.timestamp()
    os.utime(path, (ts, ts))


def hash_file(path: str, alg: str) -> str:
    hash_ = hashlib.new(alg)
    with open(path, "rb") as fh:
        hash_.update(fh.read())
    return hash_.hexdigest()


class ListExtendingOrderedDict(OrderedDict):
    """An OrderedDict subclass that aggregates list values for duplicate keys.

    This class extends OrderedDict to provide special handling for list values.
    When a list value is assigned to an existing key, the new list is extended
    onto the existing list instead of replacing it.

    In the context of configparser, this allows for accumulating multiple values
    from different sections or repeated keys, such as in multiline requirements.

    Examples:
        >>> d = MultiOrderedDict()
        >>> d["key"] = [1, 2]
        >>> d["key"] = [3, 4]
        >>> d["key"]
        [1, 2, 3, 4]
        >>> d["other"] = "value"
        >>> d["other"] = "new_value"  # Non-list values behave normally
        >>> d["other"]
        'new_value'
    """

    def __setitem__(self, key, value):
        """Sets the value for the given key, extending lists if the key exists.

        Args:
            key: The dictionary key.
            value: The value to set. If this is a list and the key already exists,
                the list will be extended to the existing value instead of replacing it.
        """
        if isinstance(value, list) and key in self:
            self[key].extend(value)
        else:
            super().__setitem__(key, value)


def download_json(index_url: str, req_name: str) -> tuple[dict, str]:
    # get information about this package from the Simple API in JSON
    # format as per PEP 691
    url = index_url.rstrip("/")
    headers = {
        "Accept": "application/vnd.pypi.simple.v1+json",
        "Accept-Encoding": "gzip",
    }
    if USER_AGENT:
        headers["User-Agent"] = USER_AGENT
    response = SESSION.get(
        f"{url}/{req_name}/",
        headers=headers,
    )
    response.raise_for_status()
    data = response.json()  # already ungzipped!
    response_url = response.url
    if data:
        return data, response_url
    msg = f"Failed loading metadata: {response}"
    raise RuntimeError(msg)


def conf_logging():
    logger = logging.getLogger()  # root
    logger.setLevel(logging.INFO)

    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter())  # %(message)s
    h.setLevel(logging.INFO)
    logger.addHandler(h)
