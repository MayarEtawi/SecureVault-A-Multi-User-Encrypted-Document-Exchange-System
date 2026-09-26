# test_version_tracker.py
"""
Pytest suite for version_tracker.py.

Run with:  pytest test_version_tracker.py -v

NOTE: this file assumes the module lives at version_tracker.py (repo
root, no crypto/pki-specific dependencies). Adjust the import below
if the real path differs.
"""

import pytest

from crypto.freshness import ReplayError, VersionTracker

DOC_A = b"doc-a"
DOC_B = b"doc-b"


@pytest.fixture
def tracker() -> VersionTracker:
    return VersionTracker()


# ============================================================
# Basic accept / reject
# ============================================================

class TestBasicAcceptReject:
    def test_first_version_is_accepted(self, tracker):
        tracker.check_and_record(DOC_A, 1)  # should not raise

    def test_first_version_need_not_be_1(self, tracker):
        # Nothing in check_and_record requires the very first version
        # seen for a document to be 1 -- only that each new call is
        # strictly greater than whatever was seen before.
        tracker.check_and_record(DOC_A, 5)  # should not raise

    def test_strictly_increasing_versions_are_accepted(self, tracker):
        tracker.check_and_record(DOC_A, 1)
        tracker.check_and_record(DOC_A, 2)
        tracker.check_and_record(DOC_A, 3)  # none of these should raise

    def test_version_can_jump_ahead(self, tracker):
        tracker.check_and_record(DOC_A, 1)
        tracker.check_and_record(DOC_A, 10)  # should not raise

    def test_repeated_version_is_replay(self, tracker):
        tracker.check_and_record(DOC_A, 5)
        with pytest.raises(ReplayError):
            tracker.check_and_record(DOC_A, 5)

    def test_lower_version_is_replay(self, tracker):
        tracker.check_and_record(DOC_A, 5)
        with pytest.raises(ReplayError):
            tracker.check_and_record(DOC_A, 3)

    def test_replay_error_message_does_not_leak_on_success_path(self, tracker):
        # Just confirms ReplayError is the specific exception type raised,
        # distinct from the ValueError used for malformed input.
        tracker.check_and_record(DOC_A, 1)
        with pytest.raises(ReplayError):
            tracker.check_and_record(DOC_A, 1)


# ============================================================
# State is not corrupted by a rejected (stale) attempt
# ============================================================

class TestStateNotCorruptedByRejection:
    def test_latest_unchanged_after_replay_attempt(self, tracker):
        tracker.check_and_record(DOC_A, 5)
        with pytest.raises(ReplayError):
            tracker.check_and_record(DOC_A, 2)
        # The stored "latest" must still be 5, not 2 -- a version
        # that was previously valid (6) must still be accepted.
        tracker.check_and_record(DOC_A, 6)  # should not raise

    def test_latest_unchanged_after_invalid_input(self, tracker):
        tracker.check_and_record(DOC_A, 5)
        with pytest.raises(ValueError):
            tracker.check_and_record(DOC_A, 0)
        with pytest.raises(ValueError):
            tracker.check_and_record(DOC_A, "not an int")
        # State must still reflect version 5, unaffected by the bad calls.
        with pytest.raises(ReplayError):
            tracker.check_and_record(DOC_A, 5)
        tracker.check_and_record(DOC_A, 6)  # should not raise


# ============================================================
# Independent tracking per document_id
# ============================================================

class TestPerDocumentIndependence:
    def test_two_documents_tracked_independently(self, tracker):
        tracker.check_and_record(DOC_A, 1)
        tracker.check_and_record(DOC_B, 1)  # independent counter, should not raise

    def test_replay_on_one_document_does_not_affect_another(self, tracker):
        tracker.check_and_record(DOC_A, 3)
        with pytest.raises(ReplayError):
            tracker.check_and_record(DOC_A, 3)
        # DOC_B is untouched and unaffected.
        tracker.check_and_record(DOC_B, 3)  # should not raise

    def test_many_documents(self, tracker):
        docs = [f"doc-{i}".encode() for i in range(20)]
        for doc in docs:
            tracker.check_and_record(doc, 1)
        for doc in docs:
            tracker.check_and_record(doc, 2)
        for doc in docs:
            with pytest.raises(ReplayError):
                tracker.check_and_record(doc, 1)


# ============================================================
# Input validation: document_id
# ============================================================

class TestDocumentIdValidation:
    def test_rejects_non_bytes_document_id(self, tracker):
        with pytest.raises(ValueError):
            tracker.check_and_record("doc-a", 1)  # str, not bytes

    def test_rejects_empty_bytes_document_id(self, tracker):
        with pytest.raises(ValueError):
            tracker.check_and_record(b"", 1)

    def test_rejects_none_document_id(self, tracker):
        with pytest.raises(ValueError):
            tracker.check_and_record(None, 1)


# ============================================================
# Input validation: version
# ============================================================

class TestVersionValidation:
    def test_rejects_non_int_version(self, tracker):
        with pytest.raises(ValueError):
            tracker.check_and_record(DOC_A, "1")
        with pytest.raises(ValueError):
            tracker.check_and_record(DOC_A, 1.0)

    def test_rejects_bool_version(self, tracker):
        # bool is a subclass of int in Python; must be explicitly rejected.
        with pytest.raises(ValueError):
            tracker.check_and_record(DOC_A, True)
        with pytest.raises(ValueError):
            tracker.check_and_record(DOC_A, False)

    def test_rejects_zero_version(self, tracker):
        with pytest.raises(ValueError):
            tracker.check_and_record(DOC_A, 0)

    def test_rejects_negative_version(self, tracker):
        with pytest.raises(ValueError):
            tracker.check_and_record(DOC_A, -1)

    def test_accepts_version_1_as_boundary(self, tracker):
        tracker.check_and_record(DOC_A, 1)  # should not raise


# ============================================================
# End-to-end-ish: simulates a sequence of authenticated shares
# ============================================================

class TestRealisticSequence:
    def test_typical_share_sequence(self, tracker):
        doc = b"contract.pdf"

        # v1 shared and accepted.
        tracker.check_and_record(doc, 1)

        # Attacker replays the v1 ShareRecord -- must be rejected.
        with pytest.raises(ReplayError):
            tracker.check_and_record(doc, 1)

        # Document is legitimately updated to v2, shared again.
        tracker.check_and_record(doc, 2)

        # Attacker now replays the (older) v1 record again -- still rejected.
        with pytest.raises(ReplayError):
            tracker.check_and_record(doc, 1)

        # And replays the v2 record too -- also rejected (not just older,
        # but also equal-to-latest must be rejected).
        with pytest.raises(ReplayError):
            tracker.check_and_record(doc, 2)

        # Legitimate v3 update proceeds normally.
        tracker.check_and_record(doc, 3)