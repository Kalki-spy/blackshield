import ssl, socket, json

host = "certifiedhacker.com"
import os
PORT = int(os.environ.get("PORT", 443))

print(f"Testing {host}:{PORT}")

# Test 1: CERT_NONE - what does getpeercert return?
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

with socket.create_connection((host, PORT), timeout=8) as sock:
    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
        print("Protocol:", ssock.version())
        print("Cipher:", ssock.cipher())
        
        cert_dict = ssock.getpeercert()
        print("getpeercert() dict:", json.dumps(cert_dict, default=str))
        
        der = ssock.getpeercert(binary_form=True)
        print("DER bytes length:", len(der) if der else "NONE")
        
        if der:
            try:
                from cryptography import x509
                import datetime as dt
                cert = x509.load_der_x509_certificate(der)
                print("cryptography parsed OK")
                try:
                    exp = cert.not_valid_after_utc
                except AttributeError:
                    exp = cert.not_valid_after
                print("Expiry:", exp)
                days = (exp.replace(tzinfo=dt.timezone.utc) if exp.tzinfo is None else exp) - dt.datetime.now(dt.timezone.utc)
                print("Days remaining:", days.days)
            except ImportError:
                print("cryptography NOT installed - using fallback")
            except Exception as e:
                print("cryptography error:", e)