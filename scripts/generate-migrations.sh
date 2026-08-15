#!/usr/bin/env bash
#
# Generates (or updates) the EF Core migration set for both providers.
#
# Migrations are generated from the model, not from a database, so nothing needs to be
# running: DesignTimeDbContextFactory supplies a placeholder connection string when none is
# configured. What it does need is the .NET SDK and the dotnet-ef tool.
#
#   scripts/generate-migrations.sh                 # add a migration named by the date
#   scripts/generate-migrations.sh AddWidgetTable  # add a migration with an explicit name
#
# Commit the result. `Database:SchemaMode=Migrate` will not start without it.

set -euo pipefail

cd "$(dirname "$0")/.."

NAME="${1:-}"
if [ -z "$NAME" ]; then
  # No Date.now() in the caller's head: a generated name still has to sort, so it is derived
  # from the date rather than left to whoever runs this.
  NAME="Schema$(date -u +%Y%m%d%H%M)"
fi

if ! dotnet tool run dotnet-ef --version >/dev/null 2>&1; then
  if ! command -v dotnet-ef >/dev/null 2>&1; then
    echo "dotnet-ef is not installed. Install it with:"
    echo "  dotnet tool install --global dotnet-ef"
    exit 1
  fi
fi

generate() {
  local provider="$1"
  local project="$2"

  echo "── ${provider} ──"

  DATABASE_PROVIDER="${provider}" \
  Database__MigrationsAssembly="${project}" \
  dotnet ef migrations add "${NAME}" \
    --project "src/${project}" \
    --startup-project src/AuthService \
    --context ApplicationDbContext
}

generate PostgreSQL AuthService.Migrations.PostgreSQL
generate SqlServer  AuthService.Migrations.SqlServer

echo
echo "Generated migration '${NAME}' for both providers."
echo "Review the DDL before committing — in particular the filtered indexes, which are the"
echo "part that differs most between the two."
