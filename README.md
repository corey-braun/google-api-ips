# google-api-ips
This script gets the IP ranges (in CIDR notation) used by Google for its APIs and services.
This is done by removing the blocks of IPs handed out to Google Cloud customers from the set of all publicly accessible Google IPs.
See https://support.google.com/a/answer/10026322 for more information.

The IPs are written to a file and/or set as the contents of an [OPNsense](https://opnsense.org/) alias.
