from pki.ca_admin import initialize_ca

initialize_ca("../ca.key", "client/trusted_ca_public.json")
print("CA ready")