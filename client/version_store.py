import json
import os
import tempfile
from pathlib import Path


STORE_PATH = Path(__file__).resolve().parent / "trusted_versions.json"


def load_versions() :
    if not STORE_PATH.exists():
        return {}

    with open(STORE_PATH, "r", encoding="utf-8") as file:
        return json.load(file)


def get_version(username: str, document_id: str) :
    versions = load_versions()
    return versions.get(username, {}).get(document_id, 0)


def save_version(username: str, document_id: str, version: int) :
    versions = load_versions()
    user_versions = versions.setdefault(username, {})

    # Never lower the client's last trusted version.
    if version <= user_versions.get(document_id, 0):
        return

    user_versions[document_id] = version

    # Replace the file after writing the complete new contents.
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=STORE_PATH.parent,
            prefix=".versions_",
            delete=False
        ) as file:
            temporary_path = file.name
            json.dump(versions, file)

        os.replace(temporary_path, STORE_PATH)
    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.remove(temporary_path)
