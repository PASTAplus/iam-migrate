#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
:Mod:
    token

:Synopsis:
    Manage user JWT

:Author:
    servilla

:Created:
    5/30/25
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import daiquiri
import jwt

from config import Config

logger = daiquiri.getLogger(__name__)


def make_token(sub: str, principal_owner: str = None ) -> str:
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": sub,
        "cn": None,
        "email": None,
        "gn": None,
        "hd": "edirepository.org",
        "iss": "https://auth.edirepository.org",
        "sn": None,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(hours=Config.JWT_TIMEOUT),
        "principals": [],
        "isEmailEnabled": False,
        "isEmailVerified": False,
        "identityId": None,
        "idpName": None,
        "idpUid": principal_owner,
        "idpCname": None,
    }
    token = jwt.encode(
        payload,
        Path(Config.PRIVATE_KEY_PATH).read_text().encode("utf-8"),
        algorithm=Config.JWT_ALGORITHM
    )
    return token
