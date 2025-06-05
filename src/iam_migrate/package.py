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
@click.argument("pid")
@click.option("-p", "--pid_file", type=click.Path(exists=True), help=help_pids)
@click.option("-a", "--all", is_flag=True, help=help_all)
def main(pid: str, pid_file: Path, all: bool):
    """
        Migrate one or more data package access states to the IAM service

        \b
        PID: PASTA data package identifier (e.g., edi.1.1)
    """
    if pid:
        migrate.migrate_package(pid)
        sys.exit(0)

    if pid_file:
        with open(pid_file, "r") as f:
            pids = f.read()
            for pid in pids:
                migrate.migrate_package(pid)
                sys.exit(0)

    if all:
        migrate.migrate_all()
        sys.exit(0)



if __name__ == '__main__':
    main()