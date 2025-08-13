#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
:Mod:
    service

:Synopsis:
    Migrate a service API authorization state to the IAM service

:Author:
    servilla

:Created:
    8/3/25
"""
import logging
from pathlib import Path

import daiquiri
from lxml import etree
from iam_lib.exceptions import IAMResponseError
from iam_lib.api.profile import ProfileClient
from iam_lib.api.resource import ResourceClient
from iam_lib.api.rule import RuleClient
from iam_lib.models.permission import Permission, PERMISSION_MAP

from config import Config
from edi_id import PASTA_ID_MAP, EDI_ID_MAP
import jwt_token

logger = daiquiri.getLogger(__name__)


def migrate(service_file: str):
    """
    Migrate a service API authorization state to the IAM service.
    Reads and parses the XML configuration file.
    
    Args:
        service_file: Path to the service XML file
    """
    if "DataPackageManager" in service_file:
        _host = Config.PACKAGE_HOST
        _port = Config.PACKAGE_PORT
        _service = Config.PACKAGE_SERVICE
    else:
        _host = Config.AUDIT_HOST
        _port = Config.AUDIT_PORT
        _service = Config.AUDIT_SERVICE

    namespaces = {
        'pasta': 'pasta://pasta.edirepository.org/service-0.1'
    }

    client_token = jwt_token.make_token(Config.CLIENT_ID)
    resource_client = _resource_client(client_token)
    rule_client = _rule_client(client_token)


    root = etree.parse(service_file)
    service_methods = root.findall("pasta:service-method", namespaces)
    for method in service_methods:
        service_name = method.get("name")
        print(f"{_host}:{_service}:{service_name}")
        resource_client.create_resource(
            resource_key=f"{_host}:{_service}:{service_name}",
            resource_type="service",
            resource_label=f"{_service}:{service_name}",
            parent_resource_key=None
        )
        allows = method.findall(".//access/allow", namespaces)
        for allow in allows:
            principal = allow.find("principal", namespaces).text
            permission = allow.find("permission", namespaces).text
            if principal in ("public", "authenticated", "vetted"):
                edi_id = EDI_ID_MAP[PASTA_ID_MAP.index(principal)]
                print(f"    {principal} ({edi_id}) - {permission}")
                rule_client.create_rule(
                    resource_key=f"{_host}:{_service}:{service_name}",
                    principal=edi_id,
                    permission=Permission(PERMISSION_MAP.index(permission)),
                )


def _resource_client(token: str):
    return ResourceClient(
        scheme=Config.SCHEME,
        host=f"{Config.AUTH_HOST}:{Config.AUTH_PORT}",
        accept=Config.ACCEPT,
        public_key_path=Config.PUBLIC_KEY_PATH,
        algorithm=Config.JWT_ALGORITHM,
        token=token,
        truststore=Config.TRUSTSTORE,
        timeout=Config.CONNECT_TIMEOUT,
    )


def _rule_client(token: str):
    return RuleClient(
        scheme=Config.SCHEME,
        host=f"{Config.AUTH_HOST}:{Config.AUTH_PORT}",
        accept=Config.ACCEPT,
        public_key_path=Config.PUBLIC_KEY_PATH,
        algorithm=Config.JWT_ALGORITHM,
        token=token,
        truststore=Config.TRUSTSTORE,
        timeout=Config.CONNECT_TIMEOUT,
    )