from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion

from .metadata import MetadataParser
from .utils import (
    download_json,
    hash_file,
    to_single_dash,
    touch_file_dt,
)

if TYPE_CHECKING:
    from packaging.requirements import Requirement


@dataclass
class MetadataCache:
    'dict(filepath: MetadataParser)'

    d: dict[str, MetadataParser] = field(default_factory=dict)

    def extract_metadata(self, filepath: str) -> MetadataParser:
        if filepath in self.d:
            return self.d[filepath]

        md = MetadataParser(filepath)

        self.d[filepath] = md
        return md


@dataclass
class ReqNamesCache:
    'set(req.name | str(req))'

    cache: set[str] = field(default_factory=set)

    def check(self, req: Requirement) -> bool:
        if self.is_simple_case(req):
            return req.name in self.cache
        return str(req) in self.cache

    def add(self, req: Requirement):
        if self.is_simple_case(req):
            self.cache.add(req.name)
        else:
            self.cache.add(str(req))

    def is_simple_case(self, req: Requirement) -> bool:
        if not req.marker and not req.extras:
            specifier = req.specifier
            if not specifier:
                return True
            # ruff: noqa: SLF001
            # pylint: disable=protected-access
            if all(spec.operator in (">", ">=") for spec in specifier._specs):
                return True
        return False


@dataclass
class JsonCache:
    'dict(req.name: data)'

    d: dict[str, dict] = field(default_factory=dict)

    # # statistics
    # # name: count
    # statd: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def get(self, url: str, name: str, *, prerelease: bool = False) -> dict:
        # # stat
        # self.statd[name] += 1
        # if self.statd[name] > 1:  # 2..18 in my test
        #     print(f'\t{self.statd[name]}: {name}')

        if name in self.d:
            return self.d[name]

        data, response_url = download_json(url, name)
        data['response_url'] = response_url

        # check metadata version ~1.0
        v_str = data["meta"]["api-version"]  # 1.4
        if not v_str:
            v_str = "1.0"
        v_int = [int(i) for i in v_str.split(".")[:2]]
        if v_int[0] != 1:
            msg = f"Unsupported metadata version {v_str}, only support 1.x"
            raise ValueError(msg)

        files = data["files"]
        if files is None or not isinstance(files, list):
            msg = "Expected response to contain a list of 'files'"
            raise ValueError(msg)

        data["files"] = enrich_files(files, prerelease=prerelease)
        self.d[name] = data
        return data


def enrich_files(files: list[dict], *, prerelease: bool = False) -> list[dict]:
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
                    to_single_dash(name),
                )
                file["is_wheel"] = False
                file["tags"] = None
            if file["version"].is_prerelease and not prerelease:
                return False
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


@dataclass
class HashCache:
    'set(filepath)'

    paths: set[str] = field(default_factory=set)

    def check_hash(self, filepath: str, hashalg: str, expected_hash: str) -> bool:
        if filepath in self.paths:
            return True

        hash_ = hash_file(filepath, hashalg)
        if hash_ != expected_hash:
            return False

        hfile = f"{filepath}.hash"
        bytes_ = f'{hashalg}={hash_}'.encode()
        if os.path.exists(hfile):
            with open(hfile, "rb") as fp:
                if bytes_ == fp.read():  # most cases
                    self.paths.add(filepath)
                    # ruff: noqa: DTZ005
                    touch_file_dt(hfile, datetime.now())
                    return True

        with open(hfile, "wb") as out:
            out.write(bytes_)
        self.paths.add(filepath)
        return True
