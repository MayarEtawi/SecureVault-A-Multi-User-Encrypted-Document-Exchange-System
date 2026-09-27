"""In-memory data store for users, protected documents, and shares."""

from __future__ import annotations

# ==============================================================================
# GLOBAL STORAGE CONTAINERS
# ==============================================================================

# Internal in-memory lookup tables
_users: dict[str, dict] = {}
_documents: dict[str, dict] = {}
_shares: dict[str, dict] = {}

# ==============================================================================
# USER MANAGEMENT
# ==============================================================================

def save_user(username: str, record: dict) -> bool:
    """
    Save a new user record to memory.

    Returns False if the username already exists to prevent overwrites.
    """
    if username in _users:
        return False

    _users[username] = record
    return True


def get_user(username: str) -> dict | None:
    """Retrieve a user record by username."""
    return _users.get(username)


def get_all_users() -> dict[str, dict]:
    """Return a dictionary of all registered users."""
    return _users

# ==============================================================================
# DOCUMENT MANAGEMENT
# ==============================================================================

def save_document(
    document_id: str,
    document: bytes,
    owner_id: str,
    filename: str,
) -> None:
    """Save an encrypted/protected document along with its ownership metadata."""
    _documents[document_id] = {
        "owner_id": owner_id,
        "filename": filename,
        "protected_document": document,
    }


def get_document_record(document_id: str) -> dict | None:
    """Retrieve full document dictionary record (metadata + payload)."""
    return _documents.get(document_id)


def get_document(document_id: str) -> bytes | None:
    """Retrieve only the protected raw document payload by document ID."""
    record = _documents.get(document_id)

    if record is None:
        return None

    return record["protected_document"]


def list_user_documents(owner_id: str) -> list[dict[str, str]]:
    """Return a list of document IDs and filenames owned by a specific user."""
    result = []

    for document_id, record in _documents.items():
        if record["owner_id"] == owner_id:
            result.append({
                "document_id": document_id,
                "filename": record["filename"],
            })

    return result

# ==============================================================================
# SHARE MANAGEMENT
# ==============================================================================

def save_share(share_id: str, share: dict) -> None:
    """Save a document sharing permission or key-wrap record."""
    _shares[share_id] = share


def get_share(share_id: str) -> dict | None:
    """Retrieve a share record by share ID."""
    return _shares.get(share_id)


def get_all_shares() -> dict[str, dict]:
    """Return a dictionary of all active shares."""
    return _shares
