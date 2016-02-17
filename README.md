HPKP Pin Generator
==================

This is a program that aims to help with the problem of PIN generation for HPKP enabled
servers. This can be a usefull if you use Let's Encrypt certificates.

In order to work, you must configure the CERTS list at __main__ function.

CERTS is a list variable containing tuples as follow: (cert_path,
cert_encoding).

The encodings can be any of the types defined at: cryptography.hazmat.primitives.serialization.Encoding

Pins has a TTL specified in pin_ttl variable. If pin_ttl exceed the expiry date
of certificate the program throws an exception.


