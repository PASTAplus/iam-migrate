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
import uuid

import click
import daiquiri
from sqlalchemy import text
from iam_lib.api.resource import ResourceClient
from iam_lib.api.rule import RuleClient

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


def migrate_data_packages(db: Database, host: str) -> None:
    resource_client = ResourceClient(
        scheme=Config.SCHEME,
        host=host,
        accept=Config.ACCEPT,
        public_key_path=Config.PUBLIC_KEY_PATH,
        algorithm=Config.ALGORITHM,
        token=Config.TOKEN,
    )

    data_packages = {}
    principals = {}

    sql = (
        "SELECT package_id, resource_id, principal_owner "
        "FROM datapackagemanager.resource_registry "
        "WHERE resource_type = 'dataPackage'"
    )
    with db.connection.connect() as conn:
        result = conn.execute(text(sql))
        for row in result:
            package_id = row[0]
            resource_id = row[1]
            principal_owner = row[2]
            # if principal_owner not in principals:
            #     principal = profile_client.create_profile(principal_owner)
            #     principals[principal_owner] = principal
            # else:
            #     principal = principals[principal_owner]
            # metadata_uuid = str(uuid.uuid1())
            # data_uuid = str(uuid.uuid1())
            # data_packages[package_id] = [resource_id, principal_owner, principal, metadata_uuid, data_uuid]
            # resource_client.create_resource(
            #     principal=principal,
            #     resource_key=row["resource_id"],
            #     resource_label=row["package_id"],
            #     resource_type="package",
            # )

    sql = (
        "SELECT resource_id, principal_owner "
    )


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

    if host == "package-d.lternet.edu":
        auth_host = "auth-d.edirepository.org"
    elif host == "package-s.lternet.edu":
        auth_host = "auth-s.edirepository.org"
    else:
        auth_host = "auth.edirepository.org"

    migrate_data_packages(db, auth_host)


if __name__ == '__main__':
    main()
