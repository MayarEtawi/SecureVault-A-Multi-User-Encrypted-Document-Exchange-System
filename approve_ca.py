from pathlib import Path
from pki.ca_admin import issue_from_request

folder = Path.home() / "SecureVault-Requests"
request = max(folder.glob("*.request.json"), key=lambda p: p.stat().st_mtime)
certificate = request.with_name(
    request.name.replace(".request.json", ".certificate.json")
)

issue_from_request(str(request), str(certificate), "../ca.key")
print("Certificate ready:", certificate)