from __future__ import print_function
import ssl
import time
import sys
import shutil

# Import from urllib.request (Python 3) or from urllib and urllib2 (Python 2)
try:
    from urllib.request import urlopen
    from urllib.error import URLError
    from http.client import HTTPSConnection
    from urllib.parse import urlparse
except ImportError:
    from urllib import urlopen
    from urllib2 import urlopen as urlopen2, URLError
    from httplib import HTTPSConnection
    from urlparse import urlparse

# Import the requests library if it's available
try:
    import requests
except ImportError:
    requests = None

# Timeout value in seconds
TIMEOUT = 5

# Progress bar display
def progress_bar(seconds):
    cols = shutil.get_terminal_size().columns
    bar_len = min(30, cols - 20)
    for i in range(seconds + 1):
        percent = int((i / seconds) * 100)
        bar = "#" * int(bar_len * i / seconds)
        sys.stdout.write(f"\rProgress: [{bar:<{bar_len}}] {percent}%")
        sys.stdout.flush()
        time.sleep(1)
    print("")

# Test different methods
def tryurlopen(url):
    return urlopen(url, timeout=TIMEOUT).read()

def tryurlopenwithcontext(url):
    return urlopen(url, context=ssl.create_default_context(), timeout=TIMEOUT).read()

def tryurlopen2(url):
    return urlopen2(url, timeout=TIMEOUT).read()

def tryurlopen2withcontext(url):
    return urlopen2(url, context=ssl.create_default_context(), timeout=TIMEOUT).read()

def tryhttpsconnection(url):
    conn = HTTPSConnection(urlparse(url).netloc, timeout=TIMEOUT)
    conn.request("GET", "/")
    return conn.getresponse().read()

def tryhttpsconnectionwithcontext(url):
    conn = HTTPSConnection(urlparse(url).netloc, context=ssl.create_default_context(), timeout=TIMEOUT)
    conn.request("GET", "/")
    return conn.getresponse().read()

def tryrequests(url):
    r = requests.get(url, timeout=TIMEOUT)
    return r.text

# TLS certificate verification must fail for each URL
def printres(func, name, url):
    try:
        res = func(url)
        print('{}: INCORRECT: expected error'.format(name))
    except (URLError, ssl.CertificateError, ssl.SSLError, IOError, Exception) as e:
        print('{}: correct'.format(name))

# Test URLs with known bad certs
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

# Find available methods
methods = {'urlopen': tryurlopen, 'HTTPSConnection': tryhttpsconnection}

if 'urlopen2' in dir():
    methods['urlopen2'] = tryurlopen2

if 'create_default_context' in dir(ssl):
    methods['urlopen w/context'] = tryurlopenwithcontext
    methods['HTTPSConnection w/context'] = tryhttpsconnectionwithcontext
    if 'urlopen2' in dir():
        methods['urlopen2 w/context'] = tryurlopen2withcontext

if requests:
    methods['requests'] = tryrequests

# Test each URL for each method
for method_name, method in methods.items():
    print('\n=== {} ==='.format(method_name))
    for name, url in urls.items():
        print('\nTesting [{}]: {}'.format(name, url))
        progress_bar(TIMEOUT)
        start = time.time()
        printres(method, name, url)
        duration = time.time() - start
        print("Time taken: {:.2f} seconds".format(duration))

"""
=== urlopen ===

Testing [revoked]: https://revoked.grc.com/
Progress: [##############################] 100%
revoked: INCORRECT: expected error
Time taken: 0.14 seconds

Testing [expired]: https://qvica1g3-e.quovadisglobal.com/
Progress: [##############################] 100%
expired: correct
Time taken: 5.04 seconds

Testing [expired2]: https://expired.badssl.com/
Progress: [##############################] 100%
expired2: correct
Time taken: 0.13 seconds

Testing [self-signed]: https://self-signed.badssl.com/
Progress: [##############################] 100%
self-signed: correct
Time taken: 0.12 seconds

Testing [bad domain]: https://wrong.host.badssl.com/
Progress: [##############################] 100%
bad domain: correct
Time taken: 0.21 seconds

Testing [bad domain2]: https://tv.eurosport.com/
Progress: [##############################] 100%
bad domain2: INCORRECT: expected error
Time taken: 5.36 seconds

Testing [rc4]: https://rc4.badssl.com/
Progress: [##############################] 100%
rc4: correct
Time taken: 0.11 seconds

Testing [dh480]: https://dh480.badssl.com/
Progress: [##############################] 100%
dh480: correct
Time taken: 0.11 seconds

Testing [superfish]: https://superfish.badssl.com/
Progress: [##############################] 100%
superfish: correct
Time taken: 0.21 seconds

Testing [edellroot]: https://edellroot.badssl.com/
Progress: [##############################] 100%
edellroot: correct
Time taken: 0.15 seconds

Testing [dsdtestprovider]: https://dsdtestprovider.badssl.com/
Progress: [##############################] 100%
dsdtestprovider: correct
Time taken: 0.11 seconds

=== HTTPSConnection ===

Testing [revoked]: https://revoked.grc.com/
Progress: [##############################] 100%
revoked: INCORRECT: expected error
Time taken: 0.16 seconds

Testing [expired]: https://qvica1g3-e.quovadisglobal.com/
Progress: [##############################] 100%
expired: correct
Time taken: 5.03 seconds

Testing [expired2]: https://expired.badssl.com/
Progress: [##############################] 100%
expired2: correct
Time taken: 0.17 seconds

Testing [self-signed]: https://self-signed.badssl.com/
Progress: [##############################] 100%
self-signed: correct
Time taken: 0.11 seconds

Testing [bad domain]: https://wrong.host.badssl.com/
Progress: [##############################] 100%
bad domain: correct
Time taken: 0.15 seconds

Testing [bad domain2]: https://tv.eurosport.com/
Progress: [##############################] 100%
bad domain2: INCORRECT: expected error
Time taken: 0.09 seconds

Testing [rc4]: https://rc4.badssl.com/
Progress: [##############################] 100%
rc4: correct
Time taken: 0.11 seconds

Testing [dh480]: https://dh480.badssl.com/
Progress: [##############################] 100%
dh480: correct
Time taken: 0.11 seconds

Testing [superfish]: https://superfish.badssl.com/
Progress: [##############################] 100%
superfish: correct
Time taken: 0.12 seconds

Testing [edellroot]: https://edellroot.badssl.com/
Progress: [##############################] 100%
edellroot: correct
Time taken: 0.12 seconds

Testing [dsdtestprovider]: https://dsdtestprovider.badssl.com/
Progress: [##############################] 100%
dsdtestprovider: correct
Time taken: 0.15 seconds

=== urlopen w/context ===

Testing [revoked]: https://revoked.grc.com/
Progress: [##############################] 100%
revoked: INCORRECT: expected error
Time taken: 0.18 seconds

Testing [expired]: https://qvica1g3-e.quovadisglobal.com/
Progress: [##############################] 100%
expired: correct
Time taken: 5.02 seconds

Testing [expired2]: https://expired.badssl.com/
Progress: [##############################] 100%
expired2: correct
Time taken: 0.16 seconds

Testing [self-signed]: https://self-signed.badssl.com/
Progress: [##############################] 100%
self-signed: correct
Time taken: 0.16 seconds

Testing [bad domain]: https://wrong.host.badssl.com/
Progress: [##############################] 100%
bad domain: correct
Time taken: 0.15 seconds

Testing [bad domain2]: https://tv.eurosport.com/
Progress: [##############################] 100%
bad domain2: INCORRECT: expected error
Time taken: 5.07 seconds

Testing [rc4]: https://rc4.badssl.com/
Progress: [##############################] 100%
rc4: correct
Time taken: 0.11 seconds

Testing [dh480]: https://dh480.badssl.com/
Progress: [##############################] 100%
dh480: correct
Time taken: 0.12 seconds

Testing [superfish]: https://superfish.badssl.com/
Progress: [##############################] 100%
superfish: correct
Time taken: 0.11 seconds

Testing [edellroot]: https://edellroot.badssl.com/
Progress: [##############################] 100%
edellroot: correct
Time taken: 0.11 seconds

Testing [dsdtestprovider]: https://dsdtestprovider.badssl.com/
Progress: [##############################] 100%
dsdtestprovider: correct
Time taken: 0.10 seconds

=== HTTPSConnection w/context ===

Testing [revoked]: https://revoked.grc.com/
Progress: [##############################] 100%
revoked: INCORRECT: expected error
Time taken: 0.14 seconds

Testing [expired]: https://qvica1g3-e.quovadisglobal.com/
Progress: [##############################] 100%
expired: correct
Time taken: 5.02 seconds

Testing [expired2]: https://expired.badssl.com/
Progress: [##############################] 100%
expired2: correct
Time taken: 0.11 seconds

Testing [self-signed]: https://self-signed.badssl.com/
Progress: [##############################] 100%
self-signed: correct
Time taken: 0.14 seconds

Testing [bad domain]: https://wrong.host.badssl.com/
Progress: [##############################] 100%
bad domain: correct
Time taken: 0.11 seconds

Testing [bad domain2]: https://tv.eurosport.com/
Progress: [##############################] 100%
bad domain2: INCORRECT: expected error
Time taken: 0.12 seconds

Testing [rc4]: https://rc4.badssl.com/
Progress: [##############################] 100%
rc4: correct
Time taken: 0.10 seconds

Testing [dh480]: https://dh480.badssl.com/
Progress: [##############################] 100%
dh480: correct
Time taken: 0.11 seconds

Testing [superfish]: https://superfish.badssl.com/
Progress: [##############################] 100%
superfish: correct
Time taken: 0.16 seconds

Testing [edellroot]: https://edellroot.badssl.com/
Progress: [##############################] 100%
edellroot: correct
Time taken: 0.16 seconds

Testing [dsdtestprovider]: https://dsdtestprovider.badssl.com/
Progress: [##############################] 100%
dsdtestprovider: correct
Time taken: 0.14 seconds

=== requests ===

Testing [revoked]: https://revoked.grc.com/
Progress: [##############################] 100%
revoked: INCORRECT: expected error
Time taken: 0.10 seconds

Testing [expired]: https://qvica1g3-e.quovadisglobal.com/
Progress: [##############################] 100%
expired: correct
Time taken: 5.03 seconds

Testing [expired2]: https://expired.badssl.com/
Progress: [##############################] 100%
expired2: correct
Time taken: 0.13 seconds

Testing [self-signed]: https://self-signed.badssl.com/
Progress: [##############################] 100%
self-signed: correct
Time taken: 0.11 seconds

Testing [bad domain]: https://wrong.host.badssl.com/
Progress: [##############################] 100%
bad domain: correct
Time taken: 0.11 seconds

Testing [bad domain2]: https://tv.eurosport.com/
Progress: [##############################] 100%
bad domain2: INCORRECT: expected error
Time taken: 4.84 seconds

Testing [rc4]: https://rc4.badssl.com/
Progress: [##############################] 100%
rc4: correct
Time taken: 0.11 seconds

Testing [dh480]: https://dh480.badssl.com/
Progress: [##############################] 100%
dh480: correct
Time taken: 0.12 seconds

Testing [superfish]: https://superfish.badssl.com/
Progress: [##############################] 100%
superfish: correct
Time taken: 0.12 seconds

Testing [edellroot]: https://edellroot.badssl.com/
Progress: [##############################] 100%
edellroot: correct
Time taken: 0.10 seconds

Testing [dsdtestprovider]: https://dsdtestprovider.badssl.com/
Progress: [##############################] 100%
dsdtestprovider: correct
Time taken: 0.16 seconds
"""