#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
:Mod:
    migrate

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

import package
import service


CWD = Path(".").resolve().as_posix()
LOGFILE = CWD + "/migrate.log"
daiquiri.setup(
    level=logging.INFO,
    outputs=(
        daiquiri.output.File(LOGFILE),
        "stdout",
    ),
)
logger = daiquiri.getLogger(__name__)


help_pid_file = "Path to file containing one or more package identifiers, one per line."
help_service_file = "Path to service file containing the PASTA service API access control rules."
help_db = "Self-discover (in datapackagemanager.resource_registry) all host package identifiers."


CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])
@click.command(context_settings=CONTEXT_SETTINGS)
@click.argument("pids", nargs=-1)
@click.option("--db", is_flag=True, help=help_db)
@click.option("--pid_file", type=click.Path(exists=True), help=help_pid_file)
@click.option("--service_file", type=click.Path(exists=True), help=help_service_file)
def main(pids: tuple, db: bool, pid_file: str, service_file: str):
    """
        Migrate one or more data package access states to the IAM service

        \b
        PIDS: PASTA data package identifier(s) (e.g., edi.1.1 edi.2.1 ...)
    """

    if len(pids) >= 1:
        for pid in pids:
            package.migrate(pid)
    elif db:
        package.all_packages()
    elif pid_file:
        with open(pid_file, "r") as f:
            pids = f.readlines()
            for pid in pids:
                package.migrate(pid.strip())
    elif service_file:
       service.migrate(service_file)
    else:
        logger.warning("No actions requested, perhaps you should run -h or --help for help. Exiting, bye!")

    sys.exit(0)


if __name__ == '__main__':
    main()
