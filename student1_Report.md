## Password Protection, Document Handling, and Sharing

### Threat Model and Scope

SecureVault is designed around an untrusted document server. We assume that an attacker may read, replace, delete, or replay objects stored by the server, including encrypted documents, credential records, certificates, and share records. The attacker may also observe information that the application deliberately leaves visible, such as document identifiers, owners, sizes, versions, and activity times. Our goal is to keep document contents and private keys confidential and to detect unauthorized changes when a client retrieves a document or accepts a share. We do not assume that encryption can force the server to keep files available. Protection of a compromised user device and recovery after a forgotten password are outside the current design.

### Password Protection and Registration

During registration, the client generates a fresh 16-byte salt and applies Argon2id to the UTF-8 password. Our selected parameters are 128 MiB of memory, three iterations, and one processing lane; the output is a 32-byte password verifier. The salt, verifier, and parameters are stored in the credential record. The plaintext password is not stored. The salt is public: its purpose is to make equal passwords produce different verifiers and to prevent reuse of precomputed password-guessing tables. We selected these work factors after measuring approximately 255 ms per operation in our earlier benchmark; this figure describes our measured machine and is not a guaranteed cost for an attacker with different hardware.

At login, the client obtains the stored record, recomputes Argon2id with its stored salt and parameters, and compares the resulting bytes using `secrets.compare_digest`. Argon2id was chosen over a fast hash such as SHA-256 because password guesses should be expensive, particularly after a credential database is exposed. Its memory requirement also increases the resources needed for parallel guessing. It cannot make a weak password unguessable. The password is additionally used with separate fresh salts to derive AES-128 keys that encrypt the user's ECDH and ECDSA private keys. The stored password verifier is not used directly as either encryption key.

Registration generates two P-256 key pairs. ECDH is used to establish a key for sharing a document key; ECDSA is used for signatures. Both private keys are stored only in encrypted, authenticated form. The client creates a signed certificate enrollment request, and a separate CA administrator must approve it. Before storing the credential record, the client verifies the returned CA signature, the expected username, and that both certified public keys match the keys generated for this registration. The CA private signing key must remain outside the untrusted document server. On first contact with another user, the client checks that user's certificate using its trusted copy of the CA public key before relying on the user's ECDH or ECDSA public key.

We considered direct fingerprint comparison and trust on first use. Direct comparison requires every pair of users to check keys through another trusted channel, while trust on first use does not detect substitution during the first interaction. We chose a small CA so that this check is concentrated at enrollment. Its assurance still depends on the administrator actually checking the applicant's identity and distributing the authentic CA public key.

### Uploading and Protecting a Document

The upload function reads the file on the client and prepares metadata containing a document ID, owner, version, filename, file type, size, and timestamp. A new document receives a new ID; an update keeps the ID and increases its version. The client calls `protect_document` before sending anything to the server. That function generates a fresh random **16-byte document key** for every encryption and uses AES-128-GCM with a fresh **12-byte nonce**. This includes replacement uploads: a new version receives a new document key rather than encrypting again under the old one.

In the protected object, the document ID, owner, version, size, and timestamp are clear but authenticated as GCM additional authenticated data (AAD). The filename, file type, and document bytes are inside the encrypted and authenticated payload. The integrated server also stores a separate clear filename for displaying document lists. **Therefore, the application does not hide the filename from the server**, even though the filename inside the protected object is encrypted. On download, the client compares the displayed filename with the authenticated one.

We chose GCM because it provides encryption and authentication in one mode and supports authenticated metadata through AAD. We considered AES-CTR combined with HMAC-SHA-256. Such a design would require separate encryption and MAC keys and an Encrypt-then-MAC order: authenticate the ciphertext, nonce, and relevant metadata before decrypting. Our actual document path uses GCM, so it does not use a separate document HMAC tag. The AES-GCM operation is supplied by PyCryptodome; our application implements the document formatting, metadata handling, key flow, and verification checks around it.

A fresh key for each upload means the application does not reset and reuse a nonce counter under an existing document key after a restart. The nonce is still generated randomly, so the guarantee is probabilistic rather than mathematical. Reusing a key and nonce together in GCM would be a serious failure. The implementation also limits the protected payload to approximately 2 GiB.

### Stored Document Format and Verified Download

Our protected document has the following byte-level structure:

| Field | Length | Meaning |
|---|---:|---|
| Magic value `SGCM` | 4 bytes | Identifies the format |
| Metadata length | 4 bytes, big-endian | Length of the following public metadata |
| Public metadata | Variable | Clear metadata authenticated as AAD |
| Ciphertext length | 8 bytes, big-endian | Length of the encrypted payload |
| GCM nonce | 12 bytes | Nonsecret value used for this encryption |
| Ciphertext | Length given above | Encrypted private metadata and document |
| GCM tag | 16 bytes | Authentication tag |

The GCM AAD consists of the magic value, metadata length, encoded public metadata, and ciphertext length. The client parses the object, verifies its GCM tag, and only then uses the recovered plaintext and private metadata. The download function also checks that the authenticated document ID matches the requested ID, that the owner matches when an owner is expected, that the version is not below the client's recorded minimum, and that the server's clear filename matches the authenticated filename. After these checks, the client writes to a temporary file and moves it to the chosen output path. A failed check returns an error without saving the unverified document.

### Sharing a Document

Sharing grants a recipient access to the **document key**, rather than sending the plaintext document. The sender first verifies the recipient's CA-signed certificate and expected username. The sharing component creates a fresh ephemeral P-256 ECDH key pair, combines its private key with the recipient's certified ECDH public key, and applies HKDF-SHA-256 with a fresh salt to derive a wrapping key. AES-128-GCM then encrypts and authenticates the 16-byte document key for that recipient. The recipient later uses their ECDH private key to derive the same wrapping key and recover the document key.

Wrapping alone does not prove who shared the file: anybody who knows the recipient's public key could encrypt something to it. Therefore, the sender signs a canonical share record with their **ECDSA private key**. The signed record contains the document ID, sender and recipient usernames, version, timestamp, and all fields of the wrapped key. On receipt, the client checks the sender's certificate and signature, confirms that it is the intended recipient, unwraps the document key, and uses the verified download path to authenticate and decrypt the document. A stored version value is used to reject a share whose version is no newer than one previously accepted for that document.

The ECDSA signature authenticates the **share record**, while GCM authenticates the encrypted document to someone who possesses its document key. These are different properties. The current signed share record does not contain a digest of the exact encrypted document; therefore, we should not claim that its ECDSA signature alone provides third-party proof of the exact document contents. Binding a document digest into the signed record would be required for that stronger claim.

### Security Properties and Limitations

Argon2id slows offline password guessing, and AES-GCM protects stored private keys and document contents. A fresh document key and nonce protect each encryption from unintended key–nonce reuse. GCM authentication and the download checks detect alteration of the protected document or its authenticated metadata. CA certificates protect the mapping from a username to public keys, while ECDSA authenticates the sender of a share. Version checks address replay only to the extent that the client retains a trustworthy record of previously accepted versions.

The current application still has material limitations. The socket client and server use `pickle.loads` on network responses and requests. A malicious serialized object may execute code **before** certificate or document verification; this must be replaced with a constrained serialization format and strict field and message-size validation before using the system with an untrusted peer. The server currently keeps users, documents, and shares in memory, so restarting it loses these records. The uploader also keeps document keys in client memory for the current run; restarting the client can leave an uploaded document inaccessible to its owner. Server deletion or refusal to serve a file cannot be prevented cryptographically. These are limitations of the current integrated implementation, not properties that GCM or signatures solve.