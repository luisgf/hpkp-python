HPKP Pin Generator
==================

This is a program that aims to help with the problem of PIN generation for HPKP enabled
servers. This can be a usefull if you use Let's Encrypt certificates.

HPKP stands for "Public Key Pinning Extension for HTTP"
For more information about HPKP please see the RFC at: https://tools.ietf.org/rfc/rfc7469.txt

In order to work, you must configure the ROOT_CERTS list with the root's of
your certificates.

ROOT_CERTS is a variable of type "list" containing tuples as follow: (cert_path,
cert_encoding). The encodings can be any of the types defined at: cryptography.hazmat.primitives.serialization.Encoding


Program Parameters


Usage: hpkp.py [options]

Options:
  -h, --help            show this help message and exit
  -f FILE, --file=FILE  Certificate file path to calculate HPKP pin.
  -e ENCODING, --encoding=ENCODING
                        Certificate format encoding. [PEM|DER]
  -t PIN_TTL, --ttl=PIN_TTL
                        TTL time in seconds for HPKP pin
  -u REPORT_URI, --url=REPORT_URI
                        The report URI to upload pin check errors
  -s, --subdomains      Include Subdomains



ins has a TTL specified in pin_ttl variable. If pin_ttl exceed the expiry date
of certificate the program throws an exception.

Enjoy It! - Luis González Fernández
