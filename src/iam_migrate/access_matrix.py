#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
:Mod:
    access_matrix

:Synopsis:
    Migrates data package ACLs to IAM

:Author:
    servilla

:Created:
    5/18/25
"""
import logging
from pathlib import Path

import daiquiri

from iam_migrate.database import Connection


CWD = Path(".").resolve().as_posix()
LOGFILE = CWD + "/access_matrix.log"
daiquiri.setup(
    level=logging.INFO,
    outputs=(
        daiquiri.output.File(LOGFILE),
        "stdout",
    ),
)
logger = daiquiri.getLogger(__name__)
