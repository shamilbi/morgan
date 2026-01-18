import hashlib
import json
import os
import re
import urllib.parse
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterable, Optional, Set

import dateutil  # type: ignore[import-untyped]
from packaging.requirements import Requirement
from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion


def to_single_dash(filename):
    "https://packaging.python.org/en/latest/specifications/version-specifiers/#version-specifiers"

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


class Cache:  # pylint: disable=protected-access
    def __init__(self):
        self.cache: set[str] = set()

    def check(self, req: Requirement) -> bool:
        if self.is_simple_case(req):
            return req.name in self.cache
        return str(req) in self.cache

    def add(self, req: Requirement):
        if self.is_simple_case(req):
            self.cache.add(req.name)
        else:
            self.cache.add(str(req))

    def is_simple_case(self, req):
        if not req.marker and not req.extras:
            specifier = req.specifier
            if not specifier:
                return True
            if all(spec.operator in (">", ">=") for spec in specifier._specs):
                return True
        return False


def is_requirement_relevant(
    requirement: Requirement, envs: Iterable[Dict], extras: Optional[Set[str]] = None
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
    envs: Iterable[Dict],
    extras: Optional[Set[str]] = None,
) -> Set[Requirement]:
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
    "upload-time: 2025-05-28T18:46:29.349478Z"
    time_str = fileinfo.get("upload-time")
    if not path or not time_str:
        return
    dt = dateutil.parser.parse(time_str)
    touch_file_dt(path, dt)


def touch_file_dt(path: str, dt: datetime):
    ts = dt.timestamp()
    os.utime(path, (ts, ts))


@dataclass
class RequestCache:  # pylint: disable=too-few-public-methods
    d: dict[str, dict] = field(default_factory=dict)  # name: data

    # # statistics
    # # name: count
    # statd: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def get(self, url: str, name: str) -> dict:
        # # stat
        # self.statd[name] += 1
        # if self.statd[name] > 1:  # 2..18 in my test
        #     print(f'\t{self.statd[name]}: {name}')

        if name in self.d:
            return self.d[name]

        if not url.endswith('/'):
            url += '/'

        # get information about this package from the Simple API in JSON
        # format as per PEP 691
        request = urllib.request.Request(
            f"{url}{name}/",
            headers={
                "Accept": "application/vnd.pypi.simple.v1+json",
            },
        )

        with urllib.request.urlopen(request) as response:
            data = json.load(response)
            data['response_url'] = str(response.url)

        # check metadata version ~1.0
        v_str = data["meta"]["api-version"]  # 1.4
        if not v_str:
            v_str = "1.0"
        v_int = [int(i) for i in v_str.split(".")[:2]]
        if v_int[0] != 1:
            raise ValueError(f"Unsupported metadata version {v_str}, only support 1.x")

        files = data["files"]
        if files is None or not isinstance(files, list):
            raise ValueError("Expected response to contain a list of 'files'")

        data["files"] = enrich_files(files)
        self.d[name] = data
        return data


def enrich_files(files: list[dict]) -> list[dict]:
    '''
    1) remove files with unsupported extensions or yanked
    2) parse versions and platform tags for each file
       (file["version"], file["tags"])
    '''

    def _ext(file: dict) -> bool:
        'remove files with unsupported extensions or yanked'
        f = file['filename'].endswith
        y = file.get("yanked", False)
        return not y and (f('.whl') or f('.zip') or f('.tar.gz'))

    def _parse(file: dict) -> bool:
        'parse versions and platform tags for each file'
        name = file['filename']
        f = name.endswith
        try:
            if f('.whl'):
                _, file["version"], _, file["tags"] = parse_wheel_filename(name)
                file["is_wheel"] = True
            elif f('.zip') or f('.tar.gz'):
                _, file["version"] = parse_sdist_filename(
                    # fix: selenium-2.0-dev-9429.tar.gz -> 9429
                    to_single_dash(name)
                )
                file["is_wheel"] = False
                file["tags"] = None
        except (InvalidVersion, InvalidSdistFilename, InvalidWheelFilename):
            # old versions
            # expandvars-0.6.0-macosx-10.15-x86_64.tar.gz

            # ignore files with invalid version, PyPI no longer allows
            # packages with special versioning schemes, and we assume we
            # can ignore such files
            return False
        return True

    filter1 = (file for file in files if _ext(file))
    filter2 = (file for file in filter1 if _parse(file))

    files2 = list(filter2)
    files2.sort(key=lambda file: file["version"], reverse=True)
    return files2


RCACHE = RequestCache()


def hash_file(path: str, alg: str) -> str:
    hash_ = hashlib.new(alg)
    with open(path, "rb") as fh:
        hash_.update(fh.read())
    return hash_.hexdigest()


@dataclass
class HashCache:  # pylint: disable=too-few-public-methods
    paths: set[str] = field(default_factory=set)  # {filepath}

    def hash_file(self, filepath: str, hashalg: str, exphash: str) -> bool:
        if filepath in self.paths:
            return True

        hash_ = hash_file(filepath, hashalg)
        if hash_ != exphash:
            return False

        hfile = f"{filepath}.hash"
        bytes_ = f'{hashalg}={hash_}'.encode()
        if os.path.exists(hfile):
            with open(hfile, "rb") as fp:
                if bytes_ == fp.read():  # most cases
                    self.paths.add(filepath)
                    touch_file_dt(hfile, datetime.now())
                    return True

        with open(hfile, "wb") as out:
            out.write(bytes_)
        self.paths.add(filepath)
        return True


HCACHE = HashCache()


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
