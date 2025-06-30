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

from iam_lib.exceptions import IAMResponseError
from iam_lib.api.profile import ProfileClient
from iam_lib.api.resource import ResourceClient
from iam_lib.api.rule import RuleClient
from iam_lib.models.permission import Permission

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

    logger.info(f"{'*' * 10} {pid} {'*' * 10}")

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

    if principal_owner is not None:
        profile_client = _profile_client(client_token)
        logger.info(f"Creating profile for principal '{principal_owner}'")
        edi_id = profile_client.create_profile(idp_uid=principal_owner)["edi_id"]
        logger.info(f"EDI profile ID '{edi_id}' created for principal '{principal_owner}'")
        user_token = jwt_token.make_token(sub=edi_id, principal_owner=principal_owner)

        resource_keys.append(package_resource_key)
        resource_client = _resource_client(user_token)
        logger.info(f"Creating package resource '{package_resource_key}' for PID '{pid}'")
        resource_client.create_resource(
            resource_key=package_resource_key,
            resource_type="package",
            resource_label=pid,
            parent_resource_key=None
        )

        # Metadata collection
        metadata_resource_key = uuid.uuid4().hex
        logger.info(f"Creating metadata collection resource with key '{metadata_resource_key}' for PID '{pid}'")
        resource_client.create_resource(
            resource_key = metadata_resource_key,
            resource_type = "collection",
            resource_label = "Metadata",
            parent_resource_key = package_resource_key
        )

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
            resource_keys.append(eml_resource_key)
            logger.info(f"Creating EML metadata resource with key '{eml_resource_key}' for PID '{pid}'")
            resource_client.create_resource(
                resource_key=eml_resource_key,
                resource_type="metadata",
                resource_label="EML Metadata",
                parent_resource_key=metadata_resource_key
            )

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
            resource_keys.append(report_resource_key)
            logger.info(f"Creating quality report resource with key '{report_resource_key}' for PID '{pid}'")
            resource_client.create_resource(
                resource_key=report_resource_key,
                resource_type="report",
                resource_label="Quality Report",
                parent_resource_key=metadata_resource_key
            )

        # Data collection
        data_resource_key = uuid.uuid4().hex
        logger.info(f"Creating data collection resource with key '{data_resource_key}' for PID '{pid}'")
        resource_client.create_resource(
            resource_key=data_resource_key,
            resource_type="collection",
            resource_label="Data",
            parent_resource_key = package_resource_key
        )

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
                resource_keys.append(entity_resource_key)
                logger.info(f"Creating data entity resource with key '{entity_resource_key}' for PID '{pid}'")
                resource_client.create_resource(
                    resource_key=entity_resource_key,
                    resource_type="data",
                    resource_label=entity_name,
                    parent_resource_key=data_resource_key
                )

        # Create access control rules for all resource keys
        rule_client = _rule_client(user_token)
        for resource_key in resource_keys:
            access_sql = (
                "SELECT principal, permission, access_type "
                "FROM datapackagemanager.access_matrix "
                f"WHERE resource_id = '{resource_key}'"
            )

            with db.connection.connect() as conn:
                result_set = conn.execute(text(access_sql)).all()
                for row in result_set:
                    principal = row[0]
                    permission = row[1]
                    access_type = row[2]

                    if principal is not None and principal == "public":
                        edi_id = "EDI-b2757fee12634ccca40d2d689f5c0543"
                    else:
                        edi_id = profile_client.create_profile(principal)["edi_id"]

                    if permission is not None:
                        if access_type == "allow":
                            logger.info(f"Creating access rule '{principal} ({edi_id})' has '{permission}' access on '{resource_key}'")
                            try:
                                rule_client.create_rule(
                                    resource_key=resource_key,
                                    principal=edi_id,
                                    permission=Permission(permission),
                                )
                            except IAMResponseError as e:
                                if "Rule already exists" in str(e):
                                    msg = f"Ignoring: {e}"
                                    logger.error(msg)
                                else:
                                    raise e
                        else:
                            msg = f"resource_key: {resource_key}; principal: {principal}; permission: {permission}"
                            logger.warning(f"**DENY** - {msg}")


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
        truststore=Config.TRUSTSTORE,
        timeout=Config.TIMEOUT,
    )


def _resource_client(token: str):
    return ResourceClient(
        scheme=Config.SCHEME,
        host=Config.AUTH_HOST,
        accept=Config.ACCEPT,
        public_key_path=Config.PUBLIC_KEY_PATH,
        algorithm=Config.JWT_ALGORITHM,
        token=token,
        truststore=Config.TRUSTSTORE,
        timeout=Config.TIMEOUT,
    )


def _rule_client(token: str):
    return RuleClient(
        scheme=Config.SCHEME,
        host=Config.AUTH_HOST,
        accept=Config.ACCEPT,
        public_key_path=Config.PUBLIC_KEY_PATH,
        algorithm=Config.JWT_ALGORITHM,
        token=token,
        truststore=Config.TRUSTSTORE,
        timeout=Config.TIMEOUT,
    )