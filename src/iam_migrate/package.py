#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
:Mod:
    package

:Synopsis:
    Migrate one or more data package access states to the IAM service

:Author:
    servilla

:Created:
    5/30/25
"""
import logging
from pathlib import Path
import sys

import click
import daiquiri

import migrate

CWD = Path(".").resolve().as_posix()
LOGFILE = CWD + "/package.log"
daiquiri.setup(
    level=logging.INFO,
    outputs=(
        daiquiri.output.File(LOGFILE),
        "stdout",
    ),
)
logger = daiquiri.getLogger(__name__)


help_pids = "Path to file containing one or more package identifiers, one per line, and migrate."
help_all = "Self-discover all host package identifiers and migrate."


CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])
@click.command(context_settings=CONTEXT_SETTINGS)
@click.argument("pids", nargs=-1)
@click.option("-p", "--pid_file", type=click.Path(exists=True), help=help_pids)
@click.option("-a", "--all", is_flag=True, help=help_all)
def main(pids: tuple, pid_file: str, all: bool):
    """
        Migrate one or more data package access states to the IAM service

        \b
        PIDS: PASTA data package identifier(s) (e.g., edi.1.1 edi.2.1 ...)
    """
    if len(pids) >= 1:
        for pid in pids:
            migrate.package(pid)
        sys.exit(0)

    if pid_file:
        with open(pid_file, "r") as f:
            pids = f.readlines()
            for pid in pids:
                migrate.package(pid.strip())
            sys.exit(0)

    if all:
        migrate.all_packages()
        sys.exit(0)

    logger.warn("No PIDs provided, exiting.")
    sys.exit(0)


if __name__ == '__main__':
    main()
