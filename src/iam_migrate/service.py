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


CWD = Path(".").resolve().as_posix()
LOGFILE = CWD + "/migrate.log"
daiquiri.setup(
    level=logging.INFO,
    outputs=(
        daiquiri.output.File(LOGFILE),
        "stdout",
    ),
)
logger = daiquiri.getLogger(__name__)


def migrate(service_file: Path):
    pass
