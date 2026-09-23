# AuthService.Mcp

An MCP (Model Context Protocol) server that integrates [authservice](../../README.md) into a
consumer project. It exposes exactly one tool, `integrate`, because the point is to do the
whole integration in a single call rather than making a client sequence several steps.

`integrate` end to end:

1. Detects the consumer project's stack (ASP.NET Core, Node/Express, or Python/FastAPI) —
   or takes an explicit override.
2. Adds an `authservice` service block to the consumer's `docker-compose.yml` (creating the
   file if none exists), pointing at a pinned image tag rather than `:latest`, with the
   project's own token issuer and audience (`issuer`, by default the project directory's name),
   and with `Jwt__PublicBaseUrl` set to `authServiceUrl`, so the discovery document links the key
   set at the address your services use. Only the connection string is left for you to fill in:
   this project's own database.
3. Generates a fresh RS256 signing key under `.authservice/signing-key.pem` — a project's
   signing key must never be reused across two instances (see the main README's "API
   overview"), so `integrate` always generates a new one rather than accepting one as input.
   The key is PKCS#8 and readable only by you. The compose file mounts it into the container
   as the secret `authservice_signing_key`, and authservice reads it through
   `Jwt__PrivateKeyPath`. `.authservice/` carries a `.gitignore` of its own, so git never picks
   the key up.
4. Generates a JWT bearer validation snippet for the detected stack, checking the same issuer
   and audience. For an `http://` `authServiceUrl`, the ASP.NET Core snippet turns off
   `RequireHttpsMetadata`, with a comment to remove that once the URL is https.
5. Looks up the latest published `authservice` service release (a `v*` tag; this tool's own
   `mcp-v*` releases are skipped) to pin a real tag; falls back to `:latest` with a note in the
   output if no release exists yet.
6. Optionally (`deploy: true`) runs `docker compose up -d`.

## Running it

Requires the .NET 10 runtime, or use a self-contained single-file binary from a
[`mcp-v*` release](../../.github/workflows/publish-mcp.yml) — no .NET installation needed
in that case.

From source:

```bash
dotnet run --project src/AuthService.Mcp
```

## Configuring an MCP client

Add it to the client's `.mcp.json` (Claude Code, Claude Desktop, and other MCP clients all
read this shape):

```json
{
  "mcpServers": {
    "authservice": {
      "command": "dotnet",
      "args": ["run", "--project", "/absolute/path/to/authservice/src/AuthService.Mcp"]
    }
  }
}
```

Or, pointing at a downloaded release binary instead of building from source:

```json
{
  "mcpServers": {
    "authservice": {
      "command": "/absolute/path/to/AuthService.Mcp"
    }
  }
}
```

The archive for each platform holds a single executable, `AuthService.Mcp` (`AuthService.Mcp.exe`
on Windows).

## The `integrate` tool

| Parameter | Default | Description |
|---|---|---|
| `targetPath` | required | Absolute path to the consumer project's root directory. |
| `authServiceUrl` | `http://localhost:8080` | URL this authservice instance will be reachable at once deployed. Used in the generated JWT validation snippet's JWKS/discovery lookup. |
| `databaseProvider` | `PostgreSQL` | `PostgreSQL` or `SqlServer`, passed through to the generated `docker-compose.yml` service block. |
| `stack` | auto-detected | Override detection: `aspnetcore`, `node-express`, or `python-fastapi`. |
| `issuer` | the project directory's name | Issuer and audience of this project's tokens, set both in the compose file and in the validation snippet. Letters, digits and `. _ : / -` only. |
| `deploy` | `false` | When `true`, also runs `docker compose up -d` against the result. When `false`, only scaffolds — review the generated files first. |

`deploy: true` runs a real command against the consumer's Docker daemon. MCP clients that
prompt for confirmation on non-read-only tool calls (this one declares
`ReadOnly = false`, `Destructive = true`) will surface that before running it.

## Releasing

Same pattern as the main service's `v*`/`publish-image.yml`, but in its own `mcp-v*`
namespace so the two version independently: tag `mcp-v0.1.0`, publish a GitHub Release
against it, and `.github/workflows/publish-mcp.yml` attaches self-contained single-file
binaries for linux-x64, linux-arm64, osx-x64, osx-arm64, and win-x64 to that release.

Untick **Set as the latest release** when publishing it, so that the repository page and
`releases/latest` keep pointing at the service. `integrate` pins only `v*` releases either way.
