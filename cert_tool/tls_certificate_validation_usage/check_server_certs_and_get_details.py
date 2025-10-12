import ssl
from OpenSSL import crypto
from urllib.parse import urlparse
import time
import sys
import shutil
import socket

# Set global timeout for all sockets (in seconds)
socket.setdefaulttimeout(5)

# List of test URLs with known bad certificates
urls = {
    'revoked': 'https://revoked.grc.com/',
    'expired': 'https://qvica1g3-e.quovadisglobal.com/',
    'expired2': 'https://expired.badssl.com/',
    'self-signed': 'https://self-signed.badssl.com/',
    'bad domain': 'https://wrong.host.badssl.com/',
    'bad domain2': 'https://tv.eurosport.com/',
    'rc4': 'https://rc4.badssl.com/',
    'dh480': 'https://dh480.badssl.com/',
    'superfish': 'https://superfish.badssl.com/',
    'edellroot': 'https://edellroot.badssl.com/',
    'dsdtestprovider': 'https://dsdtestprovider.badssl.com/'
}

# Get terminal width for pretty formatting
term_width = shutil.get_terminal_size((80, 20)).columns
divider = '-' * term_width

print("\nChecking server certificates...\n")

for label, url in urls.items():
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443

        print(divider)
        print(f"[{label.upper()}] {url}")

        # Get server certificate (does not verify it)
        pem_cert = ssl.get_server_certificate((host, port))

        # Load certificate using pyOpenSSL
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert)
        subject = x509.get_subject()
        components = dict(subject.get_components())
        components = {k.decode(): v.decode() for k, v in components.items()}

        # Print extracted certificate info
        print(f"  Common Name (CN) : {components.get('CN', 'N/A')}")
        print(f"  Subject Fields   : {components}")

    except socket.timeout:
        print("  ERROR: Connection timed out", file=sys.stderr)
    except Exception as e:
        print(f"  ERROR: {e}", file=sys.stderr)

    print(divider)
    time.sleep(0.5)  # Be polite to the servers

"""
Checking server certificates...

--------------------------------------------------------------------------------
[REVOKED] https://revoked.grc.com/
  Common Name (CN) : revoked.grc.com
  Subject Fields   : {'C': 'US', 'ST': 'California', 'L': 'Laguna Niguel', 'O': 'Gibson Research Corporation', 'CN': 'revoked.grc.com'}
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
[EXPIRED] https://qvica1g3-e.quovadisglobal.com/
  ERROR: Connection timed out
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
[EXPIRED2] https://expired.badssl.com/
  Common Name (CN) : *.badssl.com
  Subject Fields   : {'OU': 'PositiveSSL Wildcard', 'CN': '*.badssl.com'}
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
[SELF-SIGNED] https://self-signed.badssl.com/
  Common Name (CN) : *.badssl.com
  Subject Fields   : {'C': 'US', 'ST': 'California', 'L': 'San Francisco', 'O': 'BadSSL', 'CN': '*.badssl.com'}
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
[BAD DOMAIN] https://wrong.host.badssl.com/
  Common Name (CN) : *.badssl.com
  Subject Fields   : {'CN': '*.badssl.com'}
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
[BAD DOMAIN2] https://tv.eurosport.com/
  Common Name (CN) : tv.eurosport.com
  Subject Fields   : {'CN': 'tv.eurosport.com'}
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
[RC4] https://rc4.badssl.com/
--------------------------------------------------------------------------------
  ERROR: [SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure (_ssl.c:1016)
--------------------------------------------------------------------------------
[DH480] https://dh480.badssl.com/
--------------------------------------------------------------------------------
  ERROR: [SSL: BAD_DH_VALUE] bad dh value (_ssl.c:1016)
--------------------------------------------------------------------------------
[SUPERFISH] https://superfish.badssl.com/
  Common Name (CN) : superfish.badssl.com
  Subject Fields   : {'C': 'US', 'ST': 'California', 'L': 'San Francisco', 'O': 'BadSSL', 'CN': 'superfish.badssl.com'}
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
[EDELLROOT] https://edellroot.badssl.com/
  Common Name (CN) : edellroot.badssl.com
  Subject Fields   : {'C': 'US', 'ST': 'California', 'L': 'San Francisco', 'O': 'BadSSL', 'CN': 'edellroot.badssl.com'}
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
[DSDTESTPROVIDER] https://dsdtestprovider.badssl.com/
  Common Name (CN) : dsdtestprovider.badssl.com
  Subject Fields   : {'C': 'US', 'ST': 'California', 'L': 'San Francisco', 'O': 'BadSSL', 'CN': 'dsdtestprovider.badssl.com'}
--------------------------------------------------------------------------------
"""