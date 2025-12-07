import hashlib
import json
import os
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime

import dateutil  # type: ignore[import-untyped]
from packaging.requirements import Requirement


def to_single_dash(filename):
    'https://packaging.python.org/en/latest/specifications/version-specifiers/#version-specifiers'

    # selenium-2.0-dev-9429.tar.gz
    m = re.search(r'-[0-9].*-', filename)
    if m:
        s2 = filename[m.start() + 1:]
        # 2.0-dev-9429.tar.gz
        s2 = s2.replace('-dev-', '.dev')
        # 2.0.dev9429.tar.gz
        s2 = s2.replace('-', '.')
        filename = filename[:m.start() + 1] + s2
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
            if all(spec.operator in ('>', '>=') for spec in specifier._specs):
                return True
        return False


def touch_file(path: str, fileinfo: dict):
    'upload-time: 2025-05-28T18:46:29.349478Z'
    time_str = fileinfo.get('upload-time')
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

    def get(self, url: str, name: str) -> dict:
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
            data = self.d[name] = json.load(response)
            data['response_url'] = str(response.url)
            return data


RCACHE = RequestCache()


def hash_file(path: str, alg: str) -> str:
    hash_ = hashlib.new(alg)
    with open(path, "rb") as fh:
        hash_.update(fh.read())
    return hash_.hexdigest()


@dataclass
class HashCache:  # pylint: disable=too-few-public-methods
    paths: set[str] = field(default_factory=set)  # name

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
