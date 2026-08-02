# Demo walkthrough

An end-to-end tour of the API using `curl` against the Docker Compose stack. Everything
below assumes `docker compose up --build` from the repo root and `jq` installed (drop the
`| jq ...` pipes and read the raw JSON if you don't have it).

## 1. Start the stack

```bash
docker compose up --build -d
docker compose logs -f authservice   # watch startup; Ctrl+C once you see "Now listening on..."
```

This starts PostgreSQL plus the service, wired together by `docker-compose.yml`. On
first boot the service seeds the `SuperAdmin`/`Admin`/`User` roles and — because
`InitialAdmin__Email` / `InitialAdmin__Password` are set in `docker-compose.yml` — a
ready-to-use `SuperAdmin` account (`admin@example.com` / `Admin123!`).

Confirm it's up:

```bash
curl -s http://localhost:8080/health
# {"status":"Healthy","service":"AuthService"}
```

Swagger UI is at http://localhost:8080/swagger if you'd rather click through it.

## 2. Register a user

`ConsentVersions` in `appsettings.json` defaults to `"2026-01-01"` for Terms/Privacy —
`acceptedTermsVersion`/`acceptedPrivacyVersion` must match exactly or registration is
rejected.

```bash
curl -s -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "Password123!",
    "acceptedTermsVersion": "2026-01-01",
    "acceptedPrivacyVersion": "2026-01-01"
  }' | tee /tmp/alice-tokens.json | jq .

ALICE_TOKEN=$(jq -r .accessToken /tmp/alice-tokens.json)
```

## 3. Fetch the profile

```bash
curl -s http://localhost:8080/api/auth/me \
  -H "Authorization: Bearer $ALICE_TOKEN" | jq .
```

## 4. Create an organization

```bash
curl -s -X POST http://localhost:8080/api/organizations \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Acme Inc", "description": "Demo organization"}' | tee /tmp/org.json | jq .

ORG_ID=$(jq -r .id /tmp/org.json)
```

## 5. Invite a second member

```bash
curl -s -X POST "http://localhost:8080/api/organizations/$ORG_ID/invite" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "bob@example.com", "role": "Member"}' | jq .
```

No email provider is configured in the demo compose file, so the invitation email isn't
actually delivered — the service logs a warning containing the token instead:

```bash
docker compose logs authservice | grep "Invitation token:" | tail -1
# warn: ... Invitation token: <the-token>. Inviter name: alice_example
```

Copy the token out of that line:

```bash
INVITE_TOKEN="<paste the token from the log line above>"
```

## 6. Register the invited user and accept

The invitation is bound to the invited email address, so Bob has to register with the
same email he was invited with before accepting:

```bash
curl -s -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "bob@example.com",
    "password": "Password123!",
    "acceptedTermsVersion": "2026-01-01",
    "acceptedPrivacyVersion": "2026-01-01"
  }' | tee /tmp/bob-tokens.json | jq .

BOB_TOKEN=$(jq -r .accessToken /tmp/bob-tokens.json)

curl -s -X POST http://localhost:8080/api/organizations/invitations/accept \
  -H "Authorization: Bearer $BOB_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"$INVITE_TOKEN\"}" | jq .
```

## 7. Confirm membership

```bash
curl -s "http://localhost:8080/api/organizations/$ORG_ID" \
  -H "Authorization: Bearer $ALICE_TOKEN" | jq '.members'
```

Bob should now show up alongside Alice.

## 8. Use the admin API

Log in as the seeded `SuperAdmin` and hit the admin endpoints:

```bash
curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "Admin123!"}' | tee /tmp/admin-tokens.json | jq .

ADMIN_TOKEN=$(jq -r .accessToken /tmp/admin-tokens.json)

curl -s http://localhost:8080/api/admin/stats \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .

curl -s http://localhost:8080/api/admin/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
```

## Tear down

```bash
docker compose down -v   # -v also drops the Postgres volume, wiping demo data
```
