# A REST server for Treetop

This is a REST server providing a REST API for [Treetop](https://github.com/terjekv/treetop-core),
a policy management framework. A CLI interface to the REST API is also provided.

See [docs/api.md](docs/api.md) for the HTTP API reference.

## Server startup

The server supports the following environment variables:

- `TREETOP_LISTEN`: The host to bind the server to (default: `localhost`)
- `TREETOP_PORT`: The port to bind the server to (default: `9999`)
- `TREETOP_WORKERS`: The number of Actix worker threads to use (default: auto based on CPU)
- `TREETOP_RAYON_THREADS`: The number of Rayon worker threads for batch evaluation (default: auto based on CPU)
- `TREETOP_PAR_THRESHOLD`: Batch size threshold to enable parallel evaluation (default: auto based on CPU)
- `TREETOP_ALLOW_UPLOAD`: Whether to allow manually uploading policies to the server. If set to `true`,
  you can upload policies via `POST` to the `/api/v1/policies` endpoint with the content type `text/plain`.
  You will need to provide the upload token in the header `X-Upload-Token`. This token is printed in the
  logs at the `warn` level when the server starts. (default: `false`)
- `TREETOP_POLICY_URL`: An optional URL for fetching the policy file (in Cedar format) (default: `None`).
- `TREETOP_POLICY_UPDATE_FREQUENCY`: The frequency (in seconds) at which to update the policy file from the
  `TREETOP_POLICY_URL` (default: `60`).
- `TREETOP_LABELS_URL`: An optional URL for fetching the label file (in JSON format) (default: `None`).
- `TREETOP_LABELS_UPDATE_FREQUENCY`: The frequency (in seconds) at which to update the label file from the
  `TREETOP_LABELS_URL` (default: `60`).
- `TREETOP_CLIENT_ALLOWLIST`: Whitelist of client IPs or CIDR blocks. Use `*` to allow all,
  or comma-separated IPv4/IPv6 addresses/CIDRs (default: `127.0.0.1,::1`).
- `TREETOP_TRUST_IP_HEADERS`: Whether to trust proxy IP headers (`X-Forwarded-For`, `Forwarded`).
  If `false`, only uses peer address (default: `true`).

### Client interaction

From the command line, you can use `curl` to interact with the API. For example, to upload a policy file, you can use:

```bash
curl -X POST http://localhost:9999/policies -H "Content-Type: text/plain" -H "X-Upload-Token: <your-upload-token>" --data-binary @testdata/default.cedar
```

To check a request, you can use:

```bash
$ curl -X POST http://localhost:9999/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{
    "principal": { "User": { "id": { "id": "alice", "namespace": [] }, "groups": [] } },
    "action": { "id": { "id": "create_host", "namespace": [] } },
    "resource": {
      "Host": {
        "name": "hostname.example.com",
        "ip":   "10.0.0.1"
      }
    }
  }'
```

Or you can use the CLI client provided in this repository. To run the CLI client, you can use:

```bash
$ cargo run --bin cli -- upload --file testdata/default.cedar --raw --token <your-upload-token>
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.32s
     Running `target/debug/cli upload --file testdata/default.cedar --raw`
Policies SHA256: c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219
Uploaded at: 2025-06-23T22:59:05.014440Z
Size: 843 bytes
$ cargo run --bin cli -- check --principal DNS::User::alice[admins] --action DNS::Action::create_host --resource-type Host --resource-id hostname.example.com --resource-attribute name=hostname.example.com --resource-attribute ip=10.0.0.1
  Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.31s
  Running `target/debug/cli check --principal DNS::User::alice[admins] --action DNS::Action::create_host --resource-type Host --resource-id hostname.example.com --resource-attribute name=hostname.example.com --resource-attribute ip=10.0.0.1`
Allow (c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219)
```

The CLI client can also be run in REPL mode:

```bash
cargo run --bin cli -- repl
```

Then you can enter commands with tab expansion and history support. For example:

```bash
policy> upload --file testdata/default.cedar --raw --token <your-upload-token>
Policies SHA256: c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219
Uploaded at: 2025-06-23T22:25:50.285684Z
Size: 843 bytes
policy> check --principal DNS::User::alice[admins] --action DNS::Action::create_host --resource-type Host --resource-id hostname.example.com --resource-attribute name=hostname.example.com --resource-attribute ip=10.0.0.1
Allow (c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219)
policy> status

treetop-cli
  Version:        0.0.1
  Built:          2025-12-16T22:04:42.072904000Z
  Git:            1e6d78a

Server
  Version:        0.0.0+g1e6d78a
  Core:           0.0.12
  Cedar:          4.8.2

Policies
  Hash:           c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219
  Updated:        2025-12-16 22:04:47.321459 UTC
  Entries:        9
  Size:           2951 bytes
  Source:         http://localhost:8080/dns.cedar
  Refresh:        every 60s
  Allow upload:   yes

Labels
  Hash:           763bcf2b17126b1546bf3ced29fab4ea661d9f5cd504689eddfef05babcc1eb3
  Updated:        2025-12-16 22:04:47.321034 UTC
  Entries:        1
  Size:           573 bytes
  Source:         http://localhost:8080/labels.json
  Refresh:        every 60s
```

The REPL keeps the last values you used with `check` so you can recall them without retyping.
After any `check`, run `show` to see them:

```bash
policy> check --principal DNS::User::alice[admins] --action DNS::Action::create_host --resource-type Host --resource-id hostname.example.com --resource-attribute name=hostname.example.com --resource-attribute ip=10.0.0.1
Allow (c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219)
policy> show

Current Settings:
  Server:         127.0.0.1:9090
  JSON output:    off
  Debug mode:     off
  Timing:         off

Last Used Values:
  Principal:      DNS::User::alice[admins]
  Action:         DNS::Action::delete_host
  Resource Type:  Host
  Resource ID:    hostname.example.com
  Attributes:
                  name=hostname.example.com
                  ip=10.0.0.1

Files:
  History:        /Users/alice/Library/Application Support/treetop-cli/history
  Config:         /Users/alice/Library/Application Support/treetop-cli/config.toml
```

In the REPL, you can omit `--principal`, `--action`, `--resource-type`, `--resource-id`, and any `--resource-attribute`
flags on subsequent `check` commands; missing fields reuse the last values shown by `show`.

### Check command syntax

- Principals: `Namespace::User::name[group1,group2]` (omit brackets if no groups). Example: `DNS::User::alice[admins]`.
- Actions: `Namespace::Action::verb`. Example: `DNS::Action::create_host`.
- Resource type: `--resource-type <Type>` (namespace optional). Example: `--resource-type Host`.
- Resource ID: required via `--resource-id <id>`. Example: `--resource-id hostname.example.com`.
- Resource attributes: repeatable `--resource-attribute key=value`. Example: `--resource-attribute ip=10.0.0.1`

## Development

There is also a `docker-compose.yml` to set up a minialist web server to host cedar policies.
This will automatically set up a web server hosting the `testdata` folder.
Currently, this will `http://localhost:8080/default.cedar` and `http://localhost:8080/labels.json`.

```bash
docker-compose up
```
