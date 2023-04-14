# Vault Plugin: Cloudflare Access

This is a standalone backend plugin for use with [Hashicorp Vault](https://www.github.com/hashicorp/vault).
This plugin provides handling of Cloudflare Access service tokens by Vault.

This plugin creates :sparkles: **zone-level** :mage: Access service tokens. If you want the regular account wide stuff, pull-requests are welcome. :neckbeard:

## Getting Started

This is a [Vault plugin](https://www.vaultproject.io/docs/internals/plugins.html)
and is meant to work with Vault. This guide assumes you have already installed Vault
and have a basic understanding of how Vault works.

Otherwise, first read this guide on how to [get started with Vault](https://www.vaultproject.io/intro/getting-started/install.html).

To learn specifically about how plugins work, see documentation on [Vault plugins](https://www.vaultproject.io/docs/internals/plugins.html).

## Installation

Currently no built release is distributed, you'll have to build from source for your chosen OS and architecture.

1. Clone this repository and change directory into the root.
2. For good measure, run some tests: `go test -v`.
3. Change directory into `cmd/vault-plugin-secrets-cloudflare-access`
4. Build the plugin `go build` and then get the SHA256 hash of the binary.
5. Install the plugin and register it with the hash, see the [Vault plugin docs](https://developer.hashicorp.com/vault/docs/plugins/plugin-architecture#plugin-registration) for more information.

## Setup (Cloudflare)

1. Sign in to your Cloudflare dashboard and head over to your [API Tokens](https://dash.cloudflare.com/profile/api-tokens) page.
2. Create a new token that has **Edit** access to **Access: Service Tokens**.
3. Keep the tab showing the secret token open for now, you shall need it.

## Setup (Vault)

1. With the plugin installed from the steps above, mount it at some endpoint of your choosing
```sh
vault secrets enable -path=cloudflare-access vault-plugin-secrets-cloudflare-access
```
2. Configure the plugin
```sh
vault write cloudflare-access/config api_token=<API token from Cloudflare in that tab you kept open>
```
3. Create a role for the zone you are going to create tokens for, see [Cloudflare docs for getting the Zone ID](https://developers.cloudflare.com/fundamentals/get-started/basic-tasks/find-account-and-zone-ids/)
```sh
vault write cloudflare-access/role/alice zone_id=<The Zone ID>
```
4. To test that it works, retrieve a new Cloudflare Access service token from Vault
```sh
vault read cloudflare-access/creds/alice
```
5. You should now have gotten a service token for Cloudflare Access, now lets revoke it (using the output `lease_id`)
```sh
vault lease revoke cloudflare-access/creds/alice/<lease id>
```

All good, remember to close that tab from the Cloudflare dashboard showing your secret API token. :pray:

## Contribute

Pull requests welcome, and be nice.
