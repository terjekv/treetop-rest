# A REST server for Treetop

This is a REST server providing a REST API for [Treetop](https://github.com/terjekv/treetop-core),
a policy management framework. A CLI interface to the REST API is also provided.

## Endpoints

Note, these endpoints are currently in development and may change in the future. This API is not yet
stable and makes a lot of assumptions about the current usage of the Treetop framework.

### `/api/v1/policies`

- `GET`: List all policies.
- `POST`: Upload a new policy file in Cedar format, if enabled.

### `/api/v1/policies/<username>`

- `GET`: List all policies for a user.

### `/api/v1/status`

- `GET`: Get the status of the policy engine, the server, and their configuration.

### `/api/v1/check`

- `POST`: Check a request for allow/deny. The format of the request is:

```json
$ curl -X POST http://localhost:9999/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{
    "principal": {
      "User": {
        "id": "alice",
        "namespace": ["DNS"],
        "groups": [
          { "id": "admins", "namespace": ["DNS"] }
        ]
      }
    },
    "action": { "id": "create_host", "namespace": ["DNS"] },
    "resource": {
      "kind": "Host",
      "id": "hostname.example.com",
      "attrs": {
        "ip":   { "type": "Ip", "value": "10.0.0.1" },
        "name": { "type": "String", "value": "hostname.example.com" }
      }
    }
  }'
```

Valid attribute types are: `String`, `Int`, `Bool`, `Ip`, and `Set`.

## Server startup

Ths requries Rust and Cargo to be installed. You can run the server with:

```bash
RUST_LOG=debug cargo run --bin server
```

The server supports the following environment variables:

- `APP_HOST`: The host to bind the server to (default: `localhost`)
- `APP_PORT`: The port to bind the server to (default: `9999`)
- `APP_WORKERS`: The number of worker threads to use (default: `4`)
- `APP_ALLOW_UPLOAD`: Whether to allow manually uploading policies to the server. If set to `true`,
  you can upload policies via `POST` to the `/api/v1/policies` endpoint with the content type `text/plain`.
  You will need to provide the upload token in the header `X-Upload-Token`. This token is printed in the
  logs at the `warn` level when the server starts. (default: `false`)
- `APP_POLICY_URL`: An optional URL for fetching the policy file (in Cedar format) (default: `None`).
- `APP_POLICY_UPDATE_FREQUENCY`: The frequency (in seconds) at which to update the policy file from the
  `APP_POLICY_URL` (default: `60`).
- `APP_LABEL_URL`: An optional URL for fetching the label file (in JSON format) (default: `None`).
- `APP_LABEL_UPDATE_FREQUENCY`: The frequency (in seconds) at which to update the label file from the
  `APP_LABEL_URL` (default: `60`).

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
  History:        /Users/alice/Library/Application Support/treetop-rest/cli_history
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
