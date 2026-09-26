# SecureVault CA and sharing demo

This integration uses the existing offline CA code. Operate the CA separately
from the document server. Do not copy the CA private key into the client project
or the document server. The public key must be installed by a trusted method.

1. CA operator initializes once: `python -m pki.admin_cli init PRIVATE_KEY_PATH PUBLIC_KEY_PATH`.
   Keep PRIVATE_KEY_PATH outside the project/server directory and preferably under
   a separate OS account or machine. Copy PUBLIC_KEY_PATH to each client's
   `pki/trusted_ca_public.json` through a trusted channel.
2. Start the document server: `python -m server.server` from the project root.
   (The original server may instead need `python server/server.py`.)
3. Start each client: `python main.py`. Select Register. Enter a unique path for
   the request JSON and a new destination path for the certificate JSON.
   The client pauses while preserving its encrypted private keys in memory.
4. CA operator examines the request file and verifies the applicant's identity
   and the key fingerprints independently. Run
   `python -m pki.admin_cli issue REQUEST_PATH CERTIFICATE_PATH PRIVATE_KEY_PATH`.
   Type APPROVE only after checking. Transfer the signed certificate to the
   requested certificate path; on the registering client press Enter.
5. After both people register, log in as sender, upload, choose Share, select
   a document and recipient. Log in as recipient, choose Receive and save.

Requires `argon2-cffi` and `pycryptodome`. This is a course demonstration:
server state and uploaded document keys are in memory; restart loses access;
the socket protocol still uses untrusted pickle and needs a safe encoding and
transport authentication before deployment. The recipient verifies CA
certificates, sender signature, GCM authentication, owner and document ID.
