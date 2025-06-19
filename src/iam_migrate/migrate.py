#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
:Mod:
    migrate

:Synopsis:
    IAM migrations

:Author:
    servilla

:Created:
    5/30/25
"""
import uuid

import daiquiri
from sqlalchemy import text

from iam_lib.exceptions import IAMLibException
from iam_lib.api.profile import ProfileClient
from iam_lib.api.resource import ResourceClient
from iam_lib.api.rule import RuleClient

from config import Config
from database import Database
import jwt_token


logger = daiquiri.getLogger(__name__)


def package(pid: str):
    """package.

    Create a data package resource tree and associated access control rules for a
    single data package revision. The resource tree follows (resource type in parens):

    pid (package)
        |-Metadata (collection)
        |   |-EML (metadata)
        |   |-Report (metadata)
        |-Data (collection)
            |-entity_1 (data)
            |-entity_2 (data)
            ...
            |-entity_N (data)

    Args:
        pid (str): package identifier

    Returns:
        None
    """

    client_token = jwt_token.make_token(Config.CLIENT_ID)
    db = Database(Config.PACKAGE_HOST)
    resource_keys = []

    # Data package resource
    package_sql = (
        "SELECT resource_id, principal_owner "
        "FROM datapackagemanager.resource_registry "
        f"WHERE package_id = '{pid}' and resource_type = 'dataPackage'"
    )

    package_resource_key = None
    principal_owner = None
    with db.connection.connect() as conn:
        row = conn.execute(text(package_sql)).one_or_none()
        if row is not None:
            package_resource_key = row[0]
            principal_owner = row[1]
            logger.info(f"package_resource_key: {package_resource_key}; principal_owner: {principal_owner}")

    if principal_owner is not None:
        profile_client = _profile_client(client_token)
        try:
            edi_id = profile_client.create_profile(principal_owner)
        except IAMLibException as e:
            logger.error(f"create_profile: {e}")
            edi_id = "EDI-6c3060965c1c42c38c5f5c7430a60966"  # Mock EDI profile identifier

        user_token = jwt_token.make_token(principal_owner, edi_id)
        resource_client = _resource_client(user_token)

        try:
            resource_keys.append(package_resource_key)
            resource_client.create_resource(
                resource_key = package_resource_key,
                resource_type = "package",
                resource_label = pid,
                parent_resource_key = None
            )
        except IAMLibException as e:
            logger.error(f"create_resource: {e}")

        # Metadata collection
        metadata_resource_key = uuid.uuid4().hex
        try:
            logger.info(f"metadata_resource_key: {metadata_resource_key}")
            resource_client.create_resource(
                resource_key = metadata_resource_key,
                resource_type = "collection",
                resource_label = "Metadata",
                parent_resource_key = package_resource_key
            )
        except IAMLibException as e:
            logger.error(f"create_resource: {e}")

        # Metadata entities
        package_sql = (
            "SELECT resource_id "
            "FROM datapackagemanager.resource_registry "
            f"WHERE package_id = '{pid}' and resource_type = 'metadata'"
        )
        eml_resource_key = None
        with db.connection.connect() as conn:
            row = conn.execute(text(package_sql)).one_or_none()
            if row is not None:
                eml_resource_key = row[0]
                logger.info(f"eml_resource_key: {eml_resource_key}")

        if eml_resource_key is not None:
            try:
                resource_keys.append(eml_resource_key)
                resource_client.create_resource(
                    resource_key=eml_resource_key,
                    resource_type="metadata",
                    resource_label="LEVEL-1-EML",
                    parent_resource_key=metadata_resource_key
                )
            except IAMLibException as e:
                logger.error(f"create_resource: {e}")

        package_sql = (
            "SELECT resource_id "
            "FROM datapackagemanager.resource_registry "
            f"WHERE package_id = '{pid}' and resource_type = 'report'"
        )
        report_resource_key = None
        with db.connection.connect() as conn:
            row = conn.execute(text(package_sql)).one_or_none()
            if row is not None:
                report_resource_key = row[0]
                logger.info(f"report_resource_key: {report_resource_key}")

        if report_resource_key is not None:
            try:
                resource_keys.append(report_resource_key)
                resource_client.create_resource(
                    resource_key=report_resource_key,
                    resource_type="report",
                    resource_label="Quality Report",
                    parent_resource_key=metadata_resource_key
                )
            except IAMLibException as e:
                logger.error(f"create_resource: {e}")

        # Data collection
        data_resource_key = uuid.uuid4().hex
        try:
            logger.info(f"data_resource_key: {data_resource_key}")
            resource_client.create_resource(
                resource_key = data_resource_key,
                resource_type = "collection",
                resource_label = "Data",
                parent_resource_key = package_resource_key
            )
        except IAMLibException as e:
            logger.error(f"create_resource: {e}")


        # Data entities
        package_sql = (
            "SELECT resource_id, filename, entity_name "
            "FROM datapackagemanager.resource_registry "
            f"WHERE package_id = '{pid}' and resource_type = 'data'"
        )
        with db.connection.connect() as conn:
            result_set = conn.execute(text(package_sql)).all()
            for row in result_set:
                entity_resource_key = row[0]
                file_name = row[1]
                entity_name = row[2]
                try:
                    logger.info(f"entity_resource_key: {entity_resource_key}; file_name: {file_name}; entity_name: {entity_name}")
                    resource_keys.append(entity_resource_key)
                    resource_client.create_resource(
                        resource_key=entity_resource_key,
                        resource_type="data",
                        resource_label=f"{file_name}: {entity_name}",
                        parent_resource_key=data_resource_key
                    )
                except IAMLibException as e:
                    logger.error(f"create_resource: {e}")

        # Create access control rules for all resource keys
        rule_client = _rule_client(user_token)
        for resource_key in resource_keys:
            access_sql = (
                "SELECT principal, permission "
                "FROM datapackagemanager.access_matrix "
                f"WHERE resource_id = '{resource_key}'"
            )

            with db.connection.connect() as conn:
                result_set = conn.execute(text(access_sql)).all()
                for row in result_set:
                    principal = row[0]
                    permission = row[1]

                    if principal is not None:
                        try:
                            edi_id = profile_client.create_profile(principal)
                        except IAMLibException as e:
                            logger.error(f"create_profile: {e}")
                            edi_id = "EDI-6c3060965c1c42c38c5f5c7430a60966"  # Mock EDI profile identifier

                    if permission is not None:
                        try:
                            msg = f"resource_key: {resource_key}; principal: {principal}; permission: {permission}"
                            if access_type == "allow":
                                logger.info(msg)
                                rule_client.create_rule(
                                    resource_key=resource_key,
                                    principal=edi_id,
                                    permission=permission,
                                )
                            else:
                                logger.warning(f"**DENY** - {msg}")
                        except IAMLibException as e:
                            logger.error(f"create_rule: {e}")


def all_packages():

    all_packages_sql = (
        "SELECT distinct(package_id) "
        "FROM datapackagemanager.resource_registry "
        f"WHERE resource_type = 'dataPackage'"
    )

    db = Database(Config.PACKAGE_HOST)

    with db.connection.connect() as conn:
        result_set = conn.execute(text(all_packages_sql)).all()
        for row in result_set:
            pid = row[0]
            package(pid=pid)


def _profile_client(token: str):
    return ProfileClient(
        scheme=Config.SCHEME,
        host=Config.AUTH_HOST,
        accept=Config.ACCEPT,
        public_key_path=Config.PUBLIC_KEY_PATH,
        algorithm=Config.JWT_ALGORITHM,
        token=token,
    )


def _resource_client(token: str):
    return ResourceClient(
        scheme=Config.SCHEME,
        host=Config.AUTH_HOST,
        accept=Config.ACCEPT,
        public_key_path=Config.PUBLIC_KEY_PATH,
        algorithm=Config.JWT_ALGORITHM,
        token=token,
    )


def _rule_client(token: str):
    return RuleClient(
        scheme=Config.SCHEME,
        host=Config.AUTH_HOST,
        accept=Config.ACCEPT,
        public_key_path=Config.PUBLIC_KEY_PATH,
        algorithm=Config.JWT_ALGORITHM,
        token=token,
    )