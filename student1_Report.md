Here is a revised, more human, and approachable version of the text, keeping all the essential security and architectural details intact while making the tone conversational, engaging, and easy to read.

---

## Password Protection, Document Handling, and Sharing

### The Threat Model and What We're Up Against

Welcome to **SecureVault**. We're building this system around the reality of an untrusted document server. That means we have to assume an attacker might try to read, replace, delete, or replay anything the server holds—whether that is encrypted documents, credentials, certificates, or share records.

At the same time, we know the server can see certain things by design, like document IDs, owners, file sizes, versions, and when activity happened. Our main goal is simple: keep your document contents and private keys totally confidential, and catch any unauthorized tampering the moment a client tries to download a file or accept a share. Of course, encryption can't force a server to keep files online if it decides to go offline, and recovering a forgotten password or protecting a physically compromised device are outside what this design can fix.

---

### Passwords, Registration, and Keys

When you register, your client doesn't just save your password—that would be a security nightmare. Instead, it generates a fresh **16-byte salt** and runs your UTF-8 password through **Argon2id**.

* We chose strong work factors: **128 MiB of memory, 3 iterations, and 1 processing lane**, yielding a **32-byte password verifier**.
* On our benchmark machine, this took about **255 ms** per operation. (Keep in mind, that's just our hardware; an attacker with specialized rigs might have different speeds).

Why Argon2id? Unlike fast hashes like SHA-256, we *want* password guesses to be painfully expensive, especially if a credential database ever leaks. The heavy memory requirement also makes parallel guessing attacks much harder. (Though, fair warning: a strong algorithm won't magically save a weak password from being guessed). We also use separate fresh salts with your password to derive AES-128 keys that securely lock away your ECDH and ECDSA private keys.

**The Certificate Authority (CA) Setup:**
Registration also creates two P-256 key pairs—one for ECDH (key sharing) and one for ECDSA (signatures). These private keys are stored only in encrypted, authenticated form.

1. Your client submits a signed certificate enrollment request.
2. A separate CA administrator has to manually approve it.
3. Before saving your credentials, your client verifies the CA's signature, your username, and makes sure the certified public keys match what you generated.

We deliberately chose a small, centralized CA rather than Trust On First Use (TOFU). While it means the CA admin actually has to verify who you are, it saves everyone from the headache of manually cross-checking fingerprints over separate trusted channels.

---

### Uploading and Protecting a Document

When you upload a file, your client reads it and gathers metadata: a document ID, owner, version, filename, file type, size, and timestamp. Brand-new documents get a brand-new ID; updates keep the same ID but bump up the version number.

Before anything touches the network, `protect_document` kicks in:

* It generates a fresh, random **16-byte document key** for every single encryption (even for replacement uploads—we never reuse an old document key).
* It encrypts the payload using **AES-128-GCM** with a fresh **12-byte nonce**.

**What the Server Can (and Can't) See:**
In the protected object, things like the document ID, owner, version, size, and timestamp are left clear, but they are fully authenticated as GCM **Additional Authenticated Data (AAD)**. The filename, file type, and actual document bytes are safely encrypted inside.

* Fun fact: The integrated server also stores a separate, clear filename just so it can display nice document lists to you. Because of this, **the application doesn't hide the filename from the server**, even though the copy inside the protected package is encrypted. When you download it, your client simply double-checks that the displayed filename matches the authenticated one.

We chose GCM because it handles both encryption and authentication in one go while supporting AAD. Plus, generating a fresh key for every upload means we don't have to worry about resetting and reusing a nonce counter under an existing key after a restart. The nonce is generated randomly, and our implementation caps protected payloads at around **2 GiB** to stay safe.

---

### Stored Document Format and Verified Download

Whenever a file is saved, it follows a strict byte-level layout:

| Field | Length | Meaning |
| --- | --- | --- |
| Magic value `SGCM` | 4 bytes | Identifies the format |
| Metadata length | 4 bytes, big-endian | Length of the following public metadata |
| Public metadata | Variable | Clear metadata authenticated as AAD |
| Ciphertext length | 8 bytes, big-endian | Length of the encrypted payload |
| GCM nonce | 12 bytes | Nonsecret value used for this encryption |
| Ciphertext | Length given above | Encrypted private metadata and document |
| GCM tag | 16 bytes | Authentication tag |

When downloading, the client reads this structure, verifies the GCM tag *first*, and only touches the plaintext if the tag checks out. It also performs a series of safety checks:

* Does the authenticated document ID match what was requested?
* Does the owner match expectations?
* Is the version at least as new as the client's recorded minimum?
* Does the server's clear filename match the authenticated filename?

If any of these checks fail, the download stops immediately, throwing an error without saving a single byte of unverified data. If it passes, it safely writes to a temporary file before moving it to your final destination.

---

### Sharing a Document with Friends (or Colleagues)

When you share a document, you aren't emailing the plaintext file—you are granting the recipient access to the **document key**.

Here is how the magic happens:

1. The sender verifies the recipient's CA-signed certificate and username.
2. The sender creates a fresh ephemeral P-256 ECDH key pair, combines its private key with the recipient's certified ECDH public key, and runs **HKDF-SHA-256** with a fresh salt to build a wrapping key.
3. **AES-128-GCM** encrypts and authenticates the 16-byte document key specifically for that recipient.

**Proving Who Sent It:**
Encryption alone doesn't prove *who* shared the file, since anyone with the recipient's public key could technically encrypt something to them. To fix this, the sender signs a canonical **share record** using their **ECDSA private key**. This signed record includes the document ID, sender and recipient usernames, version, timestamp, and all the wrapped key details.

When the recipient opens it, their client checks the sender's certificate and signature, unwraps the document key, and runs it through the verified download path. We also check version values to make sure nobody can replay an old, stale share.

> **A Quick Security Note:** The ECDSA signature authenticates the *share record*, while GCM authenticates the *encrypted document*. They do different jobs! Because the current signed share record doesn't embed a cryptographic digest of the exact encrypted document contents, we can't claim its signature alone acts as an ironclad third-party proof of the file's exact contents. Binding a document digest directly into the signed record would be the next step for that kind of ironclad proof.

---

### Where We Stand: Security & Limitations

Let's be completely transparent about what SecureVault does well and where its current edges are:

* **The Good:** Argon2id keeps offline password cracking slow and painful. AES-GCM protects your private keys and documents at rest. Fresh nonces and keys prevent nasty reuse bugs. CA certificates and ECDSA signatures keep identities and shares honest.
* **The Caveats:** The current implementation has some material limitations we want you to know about. For starters, the socket client and server currently use `pickle.loads` on network messages. **An attacker could theoretically send a malicious serialized object that executes code *before* certificate or document verification happens.** We definitely need to swap this out for a safer serialization format and strict message-size limits before letting it loose on untrusted networks.

Additionally, the server keeps users, documents, and shares purely in memory (so restarting it wipes those records clean), and client-side memory holds document keys during active runs. Finally, server-side deletions or refusals to serve files are fundamentally outside what cryptography can solve. These are practical quirks of our current prototype implementation—not flaws in GCM or signatures themselves!

---


