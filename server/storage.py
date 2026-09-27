users = {}
documents = {}
shares = {}


def save_user(username, record):
    if username in users:
        return False

    users[username] = record
    return True


def get_document_record(document_id):
    return documents.get(document_id)

def get_user(username):
    return users.get(username)



def get_all_users():
    return users



def save_document(document_id, document, owner_id,filename):
    documents[document_id] = {
        "owner_id": owner_id,
         "filename": filename,
        "protected_document": document
    }


def get_document(document_id):
    record = documents.get(document_id)

    if record is None:
        return None

    return record["protected_document"]


def list_user_documents(owner_id):
    result = []

    for document_id, record in documents.items():
        if record["owner_id"] == owner_id:
            result.append({
                "document_id": document_id,
                "filename": record["filename"]
            })

    return result





def save_share(share_id, share):
    shares[share_id] = share



def get_share(share_id):
    return shares.get(share_id)



def get_all_shares():
    return shares
