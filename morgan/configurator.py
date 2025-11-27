import argparse
import configparser
import os
import platform
import sys
from collections import OrderedDict
from importlib import metadata


def generate_env(name: str = "local"):
    """
    Generate a configuration block for the local client environment. This is
    an implementation of the PEP 508 specification of "Environment Markers".
    Resulting block is printed to standard output, and can either be copied to
    the configuration file, or piped to it using shell redirection (e.g. `>>`).
    """

    config = configparser.ConfigParser()
    v12 = ''.join(platform.python_version_tuple()[:2])  # 313
    env_name = f'env.{name}'
    # template
    d = config[env_name] = {
        'os_name': os.name,
        'platform_python_implementation': platform.python_implementation(),
        'python_version': '.'.join(platform.python_version_tuple()[:2]),
        'python_full_version': platform.python_version(),
        'implementation_name': sys.implementation.name,
        'whl.tag.interpreter': f'(cp{v12}|py3)$',
        'whl.tag.abi': f'(cp{v12}|cp{v12}t|abi3|none)$',
    }
    d = dict(d)
    if os.name == 'posix':
        d['whl.tag.platform'] = '(manylinux.*_x86_64|any)$'
        config[f"{env_name}.posix"] = d.copy()

        d['os_name'] = 'nt'
        d['whl.tag.platform'] = '(win_amd64|win32)$'
        config[f"{env_name}.nt"] = d.copy()
    else:
        d['whl.tag.platform'] = '(win_amd64|win32)$'
        config[f"{env_name}.nt"] = d.copy()

        d['os_name'] = 'posix'
        d['whl.tag.platform'] = '(manylinux.*_x86_64|any)$'
        config[f"{env_name}.posix"] = d.copy()
    del config[env_name]
    config.write(sys.stdout)


def generate_reqs(mode: str = ">="):
    """
    Generate a requirements configuration block from current environment.

    The requirements block is printed to standard output,
    and can either be copied to the configuration file, or piped to it
    using shell redirection (e.g. `>>`).

    Args:
        mode (str, optional):
            Mode to use for versioning. Use "==" for exact versioning,
            ">=" for minimum versioning, or "<=" for maximum versioning.
            Defaults to ">=".
    """
    requirements = {dist.metadata["Name"].lower(): f"{mode}{dist.version}"
                    for dist in metadata.distributions()}
    config = configparser.ConfigParser()
    config["requirements"] = OrderedDict(sorted(requirements.items()))
    config.write(sys.stdout)


def add_arguments(parser: argparse.ArgumentParser):
    """
    Adds command line options specific to this script to an argument parser.
    """

    parser.add_argument(
        '-e', '--env',
        dest='env',
        help='Name of environment to configure'
    )

    parser.add_argument(
        '-m', '--mode',
        dest='mode',
        choices=['>=', '==', '<='],
        default=">=",
        help='Versioning mode for requirements',
    )
