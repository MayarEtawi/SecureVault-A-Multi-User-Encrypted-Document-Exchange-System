"""Replay protection for already-authenticated document records."""


class ReplayError(Exception):
    """Raised when an authenticated document version is stale."""


class VersionTracker:
    def __init__(self) -> None:
        self._latest: dict[bytes, int] = {}

    def check_and_record(self, document_id: bytes, version: int) -> None:
        """Accept a strictly newer version.

        Call this only after GCM and signature verification.  A real client
        must persist this state safely; an in-memory dictionary is only the
        library-baseline demonstration.
        """
        if not isinstance(document_id, bytes) or not document_id:
            raise ValueError("document_id must be non-empty bytes")
        if not isinstance(version, int) or isinstance(version, bool) or version < 0:
            raise ValueError("version must be a non-negative integer")

        latest = self._latest.get(document_id, -1)
        if version <= latest:
            raise ReplayError("Stale document rejected")
        self._latest[document_id] = version

