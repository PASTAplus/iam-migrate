#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
:Mod:
    edi_id

:Synopsis:

:Author:
    pasta

:Created:
    8/4/25
"""
import daiquiri

from config import Config


logger = daiquiri.getLogger(__name__)


PASTA_ID_MAP = ("public", "authenticated", "vetted")
EDI_ID_MAP = (Config.PUBLIC_ID, Config.AUTHENTICATED_ID, Config.VETTED_ID)
