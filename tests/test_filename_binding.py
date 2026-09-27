from client import download as download_client
from document.protect import protect_document


def test_changed_server_filename_is_rejected(monkeypatch, tmp_path):
    plaintext = b"Private document"
    metadata = {
        "document_id": "file-001",
        "owner_id": "Layla",
        "version": 1,
        "filename": "thesis-draft.pdf",
        "file_type": "application/pdf",
        "file_size": len(plaintext),
        "timestamp": "2026-09-27T00:00:00Z",
    }
    protected_document, document_key = protect_document(plaintext, metadata)

    def fake_send_request(request):
        assert request == {
            "type": "DOWNLOAD_DOCUMENT",
            "document_id": "file-001",
        }
        return {
            "status": True,
            "document": protected_document,
            "filename": "fake-name.pdf",  # Changed clear filename
        }

    monkeypatch.setattr(download_client, "send_request", fake_send_request)
    output_path = tmp_path / "received.pdf"

    accepted = download_client.download_file(
        "file-001",
        document_key,
        str(output_path),
    )

    assert accepted is False
    assert not output_path.exists()
def test_changed_list_filename_is_rejected(monkeypatch, tmp_path):
    plaintext = b"Private document"
    metadata = {
        "document_id": "file-002",
        "owner_id": "Layla",
        "version": 1,
        "filename": "thesis-draft.pdf",
        "file_type": "application/pdf",
        "file_size": len(plaintext),
        "timestamp": "2026-09-27T00:00:00Z",
    }
    protected_document, document_key = protect_document(plaintext, metadata)

    monkeypatch.setattr(
        download_client,
        "send_request",
        lambda request: {
            "status": True,
            "document": protected_document,
            "filename": "thesis-draft.pdf",
        },
    )

    output_path = tmp_path / "received.pdf"
    accepted = download_client.download_file(
        "file-002",
        document_key,
        str(output_path),
        expected_filename="fake-name.pdf",
    )

    assert accepted is False
    assert not output_path.exists()
def test_matching_filename_is_accepted(monkeypatch, tmp_path):
    plaintext = b"Private document"
    metadata = {
        "document_id": "file-003",
        "owner_id": "Layla",
        "version": 1,
        "filename": "thesis-draft.pdf",
        "file_type": "application/pdf",
        "file_size": len(plaintext),
        "timestamp": "2026-09-27T00:00:00Z",
    }
    protected_document, document_key = protect_document(plaintext, metadata)

    monkeypatch.setattr(
        download_client,
        "send_request",
        lambda request: {
            "status": True,
            "document": protected_document,
            "filename": "thesis-draft.pdf",
        },
    )

    output_path = tmp_path / "received.pdf"
    accepted = download_client.download_file(
        "file-003",
        document_key,
        str(output_path),
        expected_filename="thesis-draft.pdf",
    )

    assert accepted is True
    assert output_path.read_bytes() == plaintext
