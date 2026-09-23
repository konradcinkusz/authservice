# AuthService.Mcp

An MCP (Model Context Protocol) server that integrates [authservice](../../README.md) into a
consumer project. It exposes exactly one tool, `integrate`, because the point is to do the
whole integration in a single call rather than making a client sequence several steps.

`integrate` end to end:

1. Detects the consumer project's stack (ASP.NET Core, Node/Express, or Python/FastAPI) —
   or takes an explicit override.
2. Adds an `authservice` service block to the consumer's `docker-compose.yml` (creating the
   file if none exists), pointing at a pinned image tag rather than `:latest`.
3. Generates a fresh RS256 signing key under `.authservice/signing-key.pem` — a project's
   signing key must never be reused across two instances (see the main README's "API
   overview"), so `integrate` always generates a new one rather than accepting one as input.
4. Generates a JWT bearer validation snippet for the detected stack.
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
      "command": "/absolute/path/to/authservice-mcp"
    }
  }
}
```

## The `integrate` tool

| Parameter | Default | Description |
|---|---|---|
| `targetPath` | required | Absolute path to the consumer project's root directory. |
| `authServiceUrl` | `http://localhost:8080` | URL this authservice instance will be reachable at once deployed. Used in the generated JWT validation snippet's JWKS/discovery lookup. |
| `databaseProvider` | `PostgreSQL` | `PostgreSQL` or `SqlServer`, passed through to the generated `docker-compose.yml` service block. |
| `stack` | auto-detected | Override detection: `aspnetcore`, `node-express`, or `python-fastapi`. |
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
