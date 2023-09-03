# google-api-ips
Python script for creating/updating an [OPNsense](https://opnsense.org/) alias with the IP networks used by Google for its APIs and services.
This is done by removing the set of IPs handed out to Google Cloud customers from the set of all publicly accessible Google IPs.<br>
See https://support.google.com/a/answer/10026322 for more information.

The list of CIDR-notation IP networks can also be printed to stdout or written to a file if you are not using OPNsense.

The script uses a YAML configuration file, see the comments in `config.yml` for information on the configurable variables.

If using the script to update an OPNsense alias it is recommended to create the OPNsense API key on a user with only the permission "Firewall: Alias: Edit". This minimizes the damage that can be done if the key is compromised.

See this related blog post for details on how I use this script to connect [Home Assistant](https://www.home-assistant.io/) to Google Assistant:<br>
https://coreybraun.com/posts/google-assistant-home-assistant/
