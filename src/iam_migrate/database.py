#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
:Mod:
    database

:Synopsis:
    Sqlalchemy database connection engine.

:Author:
    servilla

:Created:
    5/18/25
"""
import urllib.parse

import daiquiri
from sqlalchemy import create_engine

from config import Config


logger = daiquiri.getLogger(__name__)


class Database:

    def __init__(self, host: str):
        db = (
            Config.DB_DRIVER
            + "://"
            + Config.DB_USER
            + ":"
            + urllib.parse.quote_plus(Config.DB_PW)
            + "@"
            + host
            + ":"
            + Config.DB_PORT
            + "/"
            + Config.DB_DB
        )

        self._connection = create_engine(db)

    @property
    def connection(self):
        return self._connection
