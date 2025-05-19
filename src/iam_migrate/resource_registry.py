#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
:Mod:
    resource_registry

:Synopsis:
    Migrates data packages and principal owners to IAM

:Author:
    servilla

:Created:
    5/18/25
"""
import logging
import sys
from pathlib import Path

import click
import daiquiri
from sqlalchemy import text

from config import Config
from database import Database


CWD = Path(".").resolve().as_posix()
LOGFILE = CWD + "/resource_registry.log"
daiquiri.setup(
    level=logging.INFO,
    outputs=(
        daiquiri.output.File(LOGFILE),
        "stdout",
    ),
)
logger = daiquiri.getLogger(__name__)


CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

@click.command(context_settings=CONTEXT_SETTINGS)
@click.argument("host", required=True)
def main(host: str):
    """
        Migrate data packages and principal owners to IAM.

        \b
        HOST: PASTA Data Package Manager host
    """
    if host not in Config.HOSTS:
        logger.error(f"Invalid host: {host}")
        sys.exit(1)
    db = Database(host)

    sql = "SELECT * FROM datapackagemanager.resource_registry"

    with db.connection.connect() as conn:
        result = conn.execute(text(sql))
        for row in result:
            print(row)


if __name__ == '__main__':
    main()
