#!/usr/bin/python
# Python Script that looks for HSTS Header of a given URL
# Jose Selvi - jselvi[a.t]pentester[d0.t]es - http://www.pentester.es
# Version 0.1 - 09/Feb/2014

# Importing
from optparse import OptionParser
import httplib
import re

# Get the full response
def get_response(url, user_agent):
    [proto, aux, hostname] = url.split("/")
    try:
        if proto == "https:":
            conn = httplib.HTTPSConnection(hostname, timeout=5)
        else:
            conn = httplib.HTTPConnection(hostname, timeout=5)
        conn.putrequest("GET", "/", skip_host=True)
        conn.putheader("Host", hostname)
        conn.putheader("User-Agent", user_agent)
        conn.endheaders()
        resobj = conn.getresponse()
    except:
        return
    return resobj


# Get only the HSTS Header
def get_hsts(url, user_agent):
    resobj = get_response(url, user_agent)
    if not resobj:
        return ""

    hsts_header = resobj.getheader("strict-transport-security")
    return hsts_header


# Get all headers
def get_headers(url, user_agent):
    resobj = get_response(url, user_agent)
    if not resobj:
        return ""

    return resobj.getheaders()


# Usage and options
usage = "usage: %prog [options]"
parser = OptionParser(usage=usage)
parser.add_option("-U", "--url", type="string", dest="url", help="Website URL (https)")
parser.add_option(
    "-R", "--raw", action="store_true", dest="raw", help="Show raw headers"
)
parser.add_option(
    "-A",
    "--user-agent",
    type="string",
    dest="user_agent",
    help="User-Agent string",
    default="Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36",
)
(options, args) = parser.parse_args()
urlre = re.compile("http(s)?://[a-zA-Z0-9.-]+(\:[0-9]+)?$")
if not options.url or not urlre.match(options.url):
    parser.print_help()
    exit()

# Chose raw headers o HSTS only
if options.raw:
    output = get_headers(options.url, options.user_agent)
else:
    output = get_hsts(options.url, options.user_agent)
# Print result
print output
