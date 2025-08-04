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
import jwt_token

logger = daiquiri.getLogger(__name__)


def migrate(service_file: str):
    """
    Migrate a service API authorization state to the IAM service.
    Reads and parses the XML configuration file.
    
    Args:
        service_file: Path to the service XML file
    """
    namespaces = {
        'pasta': 'pasta://pasta.edirepository.org/service-0.1'
    }

    client_token = jwt_token.make_token(Config.CLIENT_ID)

    root = etree.parse(service_file)
    service_methods = root.findall("pasta:service-method", namespaces)
    for method in service_methods:
        service_name = method.get("name")
        print(service_name)
        allows = method.findall(".//access/allow", namespaces)
        for allow in allows:
            principal = allow.find("principal", namespaces).text
            permission = allow.find("permission", namespaces).text
            print(f"    {principal} - {permission}")


def _resource_client(token: str):
    return ResourceClient(
        scheme=Config.SCHEME,
        host=Config.AUTH_HOST,
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
        host=Config.AUTH_HOST,
        accept=Config.ACCEPT,
        public_key_path=Config.PUBLIC_KEY_PATH,
        algorithm=Config.JWT_ALGORITHM,
        token=token,
        truststore=Config.TRUSTSTORE,
        timeout=Config.CONNECT_TIMEOUT,
    )