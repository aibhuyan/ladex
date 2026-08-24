"""Fixture: ordinary Python with zero AI relevance. Ladex must stay completely silent."""

import json
import os


def add(a, b):
    return a + b


CONFIG = "gpt-like-name-but-not-a-model"
DATA = json.dumps({"path": os.getcwd()})
