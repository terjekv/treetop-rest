# A REST server for Treetop

This is a REST server providing a REST API for [Treetop](https://github.com/terjekv/treetop-core), a policy management framework. A CLI interface to the REST API is also provided.

## Endpoints

Note, these endpoints are currently in development and may change in the future. This API is not yet stable and makes a lot of assumptions about the current usage of the Treetop framework.

`/api/v1/policies`
- `GET`: List all policies. 
- `POST`: Upload a new policy file in Cedar format (unauthenticated).

`/api/v1/policies/<username>`
- `GET`: List all policies for a user.

`/api/v1/status`
- `GET`: Get the status of the policy engine.

`/api/v1/check`
- `POST`: Check a request for allow/deny. The format of the request is:
```json
{
    "action": "action to check against",
    "principal": "user or entity making the request",
    "resource_name": "name of the resource",
    "resource_ip": "IP address of the resource"
}
```

The check endpoint will change in the future to support resource types in a more structured way.

### Return values for the endpoints...

You will get a JSON response, but the structure of the response may change. Right now you probably want to check the endpoints before making expectations about the response format. 

## Example Usage

### Server

To run the server, you need to have Rust installed. You can then build and run the server with:

```bash
$ RUST_LOG=debug cargo run --bin server
```

The server supports the following environment variables:
- `APP_HOST`: The host to bind the server to (default: `localhost`)
- `APP_PORT`: The port to bind the server to (default: `9999`)

### Client interaction

From the command line, you can use `curl` to interact with the API. For example, to upload a policy file, you can use:

```bash
$ curl -X POST http://localhost:9999/policies -H "Content-Type: text/plain"  --data-binary @policies.cedar
```

To check a request, you can use:

```bash
$ curl -X POST http://localhost:9999/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{
    "action": "create_host",
    "principal": "alice",
        "resource_name": "resource456",
        "resource_ip": "192.168.1.1"
  }'
```

Or you can use the CLI client provided in this repository. To run the CLI client, you can use:

```bash
$ cargo run --bin cli -- upload --file policies.cedar --raw
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.32s
     Running `target/debug/cli upload --file policies.cedar --raw`
Policies SHA256: 196e425f5af97dc2bc572534355b124a86089c50e3500dbfe5717ce79e5ca0db
Uploaded at: 2025-06-23T22:59:05.014440Z
Size: 843 bytes
$ cargo run --bin cli -- check --principal alice --action create_host --resource-name host.example.com --resource-ip 10.0.0.1
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.31s
     Running `target/debug/cli check --principal alice --action create_host --resource-name host.example.com --resource-ip 10.0.0.1`
Allow
```

The CLI client can also be run in REPL mode:

```bash
cargo run --bin cli -- repl
```

Then you can enter commands with tab expansion and history support. For example:

```
policy> upload --file policies.cedar --raw
Policies SHA256: 196e425f5af97dc2bc572534355b124a86089c50e3500dbfe5717ce79e5ca0db
Uploaded at: 2025-06-23T22:25:50.285684Z
Size: 843 bytes
policy> check --principal alice --action create_host --resource-name host.example.com --resource-ip 10.0.0.1
```