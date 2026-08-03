# Tutorial: wdrożenie i integracja z `authservice`

Ten dokument prowadzi krok po kroku przez cztery tematy:

1. jak uruchomić `authservice` lokalnie i wdrożyć je produkcyjnie (Fly.io),
2. jak korzystać z jego API jako klient (rejestracja, logowanie, organizacje, panel admina),
3. jak inne (zewnętrzne) aplikacje mogą wykorzystać `authservice` jako centralny serwis uwierzytelniania,
4. jak działa gotowe demo z `DEMO.md`.

Zakłada podstawową znajomość Dockera i REST API. Wszystkie polecenia `curl` są gotowe do
skopiowania.

---

## 0. Czym jest authservice

`authservice` to samodzielny mikroserwis uwierzytelniania i autoryzacji dla ASP.NET Core
(.NET 9), który udostępnia:

- konta użytkowników (rejestracja, logowanie, reset/zmiana hasła, soft-delete),
- tokeny JWT (krótkotrwały access token + długożyjący, odwoływalny refresh token),
- logowanie społecznościowe przez Google/GitHub (OAuth),
- wielotenantowe **organizacje** z rolami `Owner` / `Admin` / `Member`, zaproszeniami e-mail,
- API administracyjne (zarządzanie użytkownikami, rolami, blokadami),
- śledzenie zgód (Terms/Privacy/Cookies) pod RODO,
- PostgreSQL (domyślnie) lub SQL Server jako bazę danych.

Serwis jest projektowany tak, by **inne aplikacje (frontend, backend, mikroserwisy) nie musiały
same implementować logowania** — wystarczy, że zaufają tokenom JWT wystawianym przez ten serwis.

---

## 1. Wdrożenie krok po kroku

### 1.1. Uruchomienie lokalne przez Docker Compose (najszybsza ścieżka)

Wymagania: Docker + Docker Compose.

```bash
git clone https://github.com/konradcinkusz/authservice.git
cd authservice
docker compose up --build
```

`docker-compose.yml` uruchamia dwa kontenery:

- `postgres` — baza PostgreSQL 16,
- `authservice` — sam serwis, nasłuchujący na porcie `8080`.

Przy pierwszym starcie serwis:

- tworzy schemat bazy danych (`EnsureCreated`),
- zasiewa role `SuperAdmin` / `Admin` / `User`,
- ponieważ w `docker-compose.yml` ustawione są `InitialAdmin__Email` / `InitialAdmin__Password`,
  tworzy od razu konto `SuperAdmin` (`admin@example.com` / `Admin123!`) — gotowe do zabawy z API
  administracyjnym bez ręcznego nadawania ról.

Sprawdź, czy działa:

```bash
curl -s http://localhost:8080/health
# {"status":"Healthy","service":"AuthService"}
```

Interaktywna dokumentacja API (Swagger) jest dostępna pod `http://localhost:8080/swagger`.

> Sekrety wpisane w `docker-compose.yml` (`Jwt__SecretKey` itd.) są **wyłącznie do lokalnych
> eksperymentów** — nie używaj ich poza własną maszyną.

### 1.2. Uruchomienie lokalne bez Dockera (`dotnet run`)

Wymagania: .NET 9 SDK oraz działający PostgreSQL (lub SQL Server).

```bash
cd src/AuthService
dotnet user-secrets set "Jwt:SecretKey" "some-long-random-development-secret"
dotnet user-secrets set "ConnectionStrings:DefaultConnection" \
  "Host=localhost;Port=5432;Database=authservice_dev;Username=postgres;Password=postgres"
cd ../..
dotnet restore
dotnet run --project src/AuthService
```

Minimalna konfiguracja, którą trzeba ustawić (przez `appsettings.json`, zmienne środowiskowe lub
`dotnet user-secrets`):

| Klucz | Opis |
| --- | --- |
| `ConnectionStrings:DefaultConnection` | connection string do bazy |
| `DatabaseProvider` | `PostgreSQL` (domyślnie) lub `SqlServer` |
| `Jwt:SecretKey` | klucz symetryczny do podpisywania tokenów (min. 32 znaki) |
| `Jwt:Issuer` / `Jwt:Audience` | domyślnie `AuthService` |

Opcjonalnie: `OAuth:Google:*`, `OAuth:GitHub:*`, `SendGrid:*`, `InitialAdmin:*`,
`Cors:AllowedOrigins`, `ConsentVersions:*` — pełna lista w `README.md`.

### 1.3. Budowanie i uruchamianie własnego obrazu Docker

```bash
docker build -f src/AuthService/Dockerfile -t authservice .
docker run -p 8080:8080 \
  -e Jwt__SecretKey=some-long-random-secret \
  -e ConnectionStrings__DefaultConnection="Host=host.docker.internal;Port=5432;Database=authservice;Username=postgres;Password=postgres" \
  authservice
```

### 1.4. Wdrożenie produkcyjne na Fly.io

Repozytorium ma gotowy pipeline CI/CD (`.github/workflows/flyio.yml`), który wdraża **dwie
aplikacje Fly.io**:

- `authservice-postgres` — prywatna instancja PostgreSQL 16, dostępna tylko z wewnętrznej sieci
  Fly (`flyio/postgres.fly.toml`),
- `authservice` — sam serwis, zbudowany z `src/AuthService/Dockerfile` i wypchnięty do
  `registry.fly.io/authservice` (`flyio/authservice.fly.toml`).

Pipeline uruchamia się automatycznie po wypchnięciu tagu `v*` (czyli po opublikowaniu GitHub
Release) albo ręcznie z zakładki Actions (`workflow_dispatch`).

#### Krok 1 — konto i token Fly.io

1. Załóż konto na [fly.io](https://fly.io) (i organizację, lub użyj `personal`).
2. Zainstaluj `flyctl` i zaloguj się, a następnie wygeneruj token wdrożeniowy:

   ```bash
   fly tokens create deploy
   ```

#### Krok 2 — środowisko `production` w GitHub

1. W repozytorium GitHub wejdź w **Settings → Environments** i utwórz środowisko o nazwie
   `production`.
2. Dodaj w nim poniższe **sekrety**:

   | Sekret | Wymagany | Opis | Skąd wziąć |
   | --- | --- | --- | --- |
   | `FLY_API_TOKEN` | Tak | token wdrożeniowy Fly.io | `fly tokens create deploy` |
   | `POSTGRES_PASSWORD` | Tak | hasło do bazy Postgres na Fly | `openssl rand -base64 24` |
   | `JWT_SECRET` | Tak | klucz podpisujący JWT (min. 32 znaki) | `openssl rand -base64 32` |
   | `OAUTH_GOOGLE_CLIENT_ID` / `OAUTH_GOOGLE_CLIENT_SECRET` | Nie | logowanie przez Google | [Google Cloud Console](https://console.cloud.google.com/apis/credentials) |
   | `OAUTH_GITHUB_CLIENT_ID` / `OAUTH_GITHUB_CLIENT_SECRET` | Nie | logowanie przez GitHub | [GitHub OAuth Apps](https://github.com/settings/developers) |
   | `SENDGRID_API_KEY` / `SENDGRID_FROM_EMAIL` / `SENDGRID_FROM_NAME` | Nie | realna wysyłka e-maili (reset hasła, zaproszenia) | [SendGrid](https://sendgrid.com) |
   | `INITIAL_ADMIN_EMAIL` / `INITIAL_ADMIN_PASSWORD` | Nie | zasiewa konto `SuperAdmin` przy pierwszym starcie | dowolne |

   Opcjonalna **zmienna** repo/środowiska: `CORS_ALLOWED_ORIGIN` — origin frontendu, który ma
   mieć dostęp do API w produkcji.

3. Nazwy aplikacji `authservice` / `authservice-postgres` są **globalne na Fly.io** — jeśli są
   zajęte, zmień `APP_AUTHSERVICE` / `APP_POSTGRES` w `.github/workflows/flyio.yml` oraz
   odpowiadające im linie `app = "..."` w plikach `flyio/*.fly.toml`, zanim wykonasz pierwsze
   wdrożenie.

#### Krok 3 — wypchnięcie wdrożenia

```bash
git tag v1.0.0
git push origin v1.0.0
```

Albo z UI GitHuba: **Releases → Draft a new release**, ustaw tag `v*` i opublikuj.

Kolejność zadań w pipeline:

```
deploy-postgres ──┐
build             ──┴──▶ deploy-authservice
```

1. `deploy-postgres` — idempotentnie tworzy aplikację i wolumin Postgresa na Fly (jeśli już
   istnieją, pomija ten krok), ustawia hasło i wdraża bazę.
2. `build` — buduje obraz z `src/AuthService/Dockerfile` i wypycha go do
   `registry.fly.io/authservice` (równolegle z krokiem 1).
3. `deploy-authservice` — ustawia sekrety serwisu (`Jwt__SecretKey`, connection string do
   wewnętrznego hosta `authservice-postgres.internal`, OAuth, SendGrid, `InitialAdmin`,
   `Cors__AllowedOrigins__0`) i wdraża serwis pod zbudowanym obrazem.

Po zakończeniu serwis jest dostępny pod `https://authservice.fly.dev` (lub inną nazwą, jeśli
zmieniono `APP_AUTHSERVICE`).

#### Kolejne wdrożenia

Każdy kolejny tag `v*` powtarza cały proces — wdrożenie Postgresa jest no-opem, jeśli baza już
istnieje, a serwis dostaje nowy obraz.

### 1.5. Schemat bazy danych

Repozytorium **nie zawiera** wersjonowanych migracji EF Core — przy starcie wywoływane jest
`EnsureCreated`, żeby serwis dało się uruchomić od zera na obu wspieranych bazach. Jeśli
potrzebujesz migracji do środowiska produkcyjnego z ewoluującym schematem:

```bash
cd src/AuthService
dotnet ef migrations add InitialCreate
```

...i zmień `DatabaseProviderExtensions.InitializeDatabaseAsync`, żeby wywoływał
`context.Database.MigrateAsync()` zamiast `EnsureCreatedAsync()`.

---

## 2. Jak korzystać z authservice jako klient API

Wszystkie endpointy są pod prefiksem `/api`, pełna referencja generowana jest w
`/swagger`. Poniżej najważniejsze grupy.

### 2.1. Rejestracja i logowanie

```bash
curl -s -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "Password123!",
    "acceptedTermsVersion": "2026-01-01",
    "acceptedPrivacyVersion": "2026-01-01"
  }'
```

`acceptedTermsVersion` / `acceptedPrivacyVersion` muszą dokładnie odpowiadać wartościom z
`ConsentVersions` w konfiguracji serwisu — inaczej rejestracja zostanie odrzucona. Odpowiedź
zawiera `accessToken`, `refreshToken` i `expiresIn`.

Logowanie:

```bash
curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "Password123!"}'
```

Odświeżenie tokenu (stary refresh token zostaje odwołany, dostajesz nową parę):

```bash
curl -s -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "<refresh-token>"}'
```

Wylogowanie (`POST /api/auth/logout`) odwołuje aktywne refresh tokeny użytkownika.

### 2.2. Wywołania autoryzowane

Access token przekazujesz w nagłówku `Authorization: Bearer <token>`:

```bash
curl -s http://localhost:8080/api/auth/me \
  -H "Authorization: Bearer $ALICE_TOKEN"
```

Inne endpointy konta: `PUT /api/auth/profile`, `POST /api/auth/change-password`,
`POST /api/auth/forgot-password` / `/reset-password`, `DELETE /api/auth/account` (soft-delete),
`GET/POST /api/auth/consents`.

### 2.3. Logowanie społecznościowe (OAuth)

```
GET /api/external-auth/login?provider=Google|GitHub&returnUrl=<frontend-url>
GET /api/external-auth/callback   (wywoływane przez dostawcę OAuth)
GET /api/external-auth/providers  (lista aktywnych dostawców)
```

Frontend przekierowuje użytkownika na `/api/external-auth/login?provider=Google`, serwis
prowadzi cały handshake OAuth, a na końcu przekierowuje z powrotem na `returnUrl` z tokenami
JWT doklejonymi jako parametry query (`accessToken`, `refreshToken`, `expiresIn`). `returnUrl`
jest walidowany względem `OAuth:PostLoginRedirectBaseUrl` / `OAuth:PostLoginRedirectAllowedBaseUrls`,
żeby nie dało się przekierować tokenów na obcy serwer (ochrona przed open-redirect).

### 2.4. Organizacje (multi-tenant)

```bash
# utworzenie organizacji
curl -s -X POST http://localhost:8080/api/organizations \
  -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "Acme Inc", "description": "Demo organization"}'

# zaproszenie członka (rola Owner/Admin/Member)
curl -s -X POST "http://localhost:8080/api/organizations/$ORG_ID/invite" \
  -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" \
  -d '{"email": "bob@example.com", "role": "Member"}'

# akceptacja zaproszenia przez zaproszonego użytkownika
curl -s -X POST http://localhost:8080/api/organizations/invitations/accept \
  -H "Authorization: Bearer $BOB_TOKEN" -H "Content-Type: application/json" \
  -d '{"token": "<invite-token>"}'
```

Pozostałe: `GET/PUT/DELETE /api/organizations/{id}`, `GET /api/organizations/invitations`,
`DELETE /api/organizations/{id}/members/{userId}` / `/members/me`, `POST .../restore`.

### 2.5. API administracyjne

Wymaga roli `Admin` lub `SuperAdmin`:

```bash
curl -s http://localhost:8080/api/admin/stats -H "Authorization: Bearer $ADMIN_TOKEN"
curl -s http://localhost:8080/api/admin/users -H "Authorization: Bearer $ADMIN_TOKEN"
```

Dalej: `GET /api/admin/users/{userId}`, `/users/deleted`, `POST /api/admin/users/{userId}/roles`,
`/unlock`, `/restore`.

---

## 3. Jak zewnętrzne aplikacje mogą wykorzystać authservice

`authservice` jest pomyślany jako **centralny dostawca tożsamości** dla ekosystemu innych
usług — frontendów i backendów, które same nie implementują logowania.

### 3.1. Model integracji

1. Frontend (SPA/mobile) rozmawia z `authservice` bezpośrednio: rejestracja, logowanie, OAuth,
   odświeżanie tokenów. Przechowuje `accessToken` (krótkotrwały) i `refreshToken`
   (długożyjący, do odświeżania).
2. Frontend dołącza `accessToken` jako `Authorization: Bearer <token>` do wywołań **innych**
   usług backendowych (Twojego właściwego produktu/API).
3. **Te inne usługi nie muszą wywoływać z powrotem authservice**, żeby zweryfikować token —
   wystarczy, że znają ten sam `Jwt:SecretKey`, `Jwt:Issuer` i `Jwt:Audience` i lokalnie
   zweryfikują podpis JWT (standardowy middleware JWT Bearer, dostępny w praktycznie każdym
   frameworku: ASP.NET Core, Express + `jsonwebtoken`, FastAPI + `python-jose`, Spring Security
   itd.).

To sprawia, że autoryzacja jest **bezstanowa i szybka** — usługi produktowe nie muszą pytać
authservice przy każdym żądaniu, tylko raz zweryfikować podpis lokalnie.

### 3.2. Co jest w tokenie (claims)

Access token wystawiany przez `TokenService` zawiera m.in.:

| Claim | Znaczenie |
| --- | --- |
| `sub` / `ClaimTypes.NameIdentifier` | ID użytkownika |
| `email` | e-mail użytkownika |
| `ClaimTypes.Name` | nazwa użytkownika |
| `ClaimTypes.Role` | role globalne (`User`, `Admin`, `SuperAdmin`) — może wystąpić wielokrotnie |
| `organization` | ID organizacji, do której użytkownik należy — osobny claim na każdą organizację |
| `organization:{orgId}:role` | rola użytkownika w danej organizacji (`Owner`/`Admin`/`Member`) |

Dzięki temu zewnętrzna usługa może np. sprawdzić „czy ten użytkownik jest `Owner` w organizacji
X” bez żadnego dodatkowego zapytania sieciowego — wystarczy odczytać claimy z tokenu.

### 3.3. Przykład: weryfikacja JWT w innej usłudze ASP.NET Core

```csharp
// Program.cs innej usługi — te same wartości co w authservice
var jwtSecretKey = builder.Configuration["Jwt:SecretKey"];
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "AuthService";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "AuthService";

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecretKey)),
            ClockSkew = TimeSpan.Zero
        };
    });
```

Ta konfiguracja jest identyczna z tą w `src/AuthService/Program.cs` — wystarczy podać ten sam
sekret, issuer i audience jako zmienne środowiskowe innej usługi (np. `Jwt__SecretKey`), żeby
zaczęła akceptować tokeny wystawione przez `authservice`, bez znajomości bazy danych ani
żadnego wywołania sieciowego do authservice.

Dla usług w innych technologiach zasada jest taka sama: dowolna biblioteka JWT (HS256, klucz
symetryczny) zweryfikuje token, o ile zna ten sam `SecretKey`/`Issuer`/`Audience`.

### 3.4. Konfiguracja CORS dla frontendów

Jeśli frontend woła authservice bezpośrednio z przeglądarki, jego origin musi być wpisany w
`Cors:AllowedOrigins` (lokalnie) lub w zmienną `CORS_ALLOWED_ORIGIN` (Fly.io/produkcja).

### 3.5. Rate limiting

Endpointy uwierzytelniające (`login`, `register`, `refresh`) są ograniczone do 20 żądań/minutę
na adres IP, pozostałe API — do 200 żądań/minutę na użytkownika (lub IP dla niezalogowanych).
Integrujące się aplikacje powinny obsłużyć `429 Too Many Requests` z polem `retryAfter`.

---

## 4. Jak działa demo (`DEMO.md`)

Gotowe demo pokazuje pełny cykl życia: od rejestracji, przez organizacje, po panel admina —
wszystko przez `curl` na stosie z Docker Compose.

### Krok po kroku

1. **Start stosu**:

   ```bash
   docker compose up --build -d
   docker compose logs -f authservice   # obserwuj start, aż zobaczysz "Now listening on..."
   ```

   Przy pierwszym uruchomieniu seedowane są role oraz konto `SuperAdmin`
   (`admin@example.com` / `Admin123!`), bo `InitialAdmin__Email/Password` są ustawione w
   `docker-compose.yml`.

2. **Rejestracja Alice** — `POST /api/auth/register`, wynik zapisywany do pliku, a
   `accessToken` wyciągany do zmiennej `ALICE_TOKEN` (demo używa `jq`).

3. **Pobranie profilu** — `GET /api/auth/me` z tokenem Alice.

4. **Utworzenie organizacji** — `POST /api/organizations` jako Alice; `ORG_ID` zapisywany do
   zmiennej.

5. **Zaproszenie drugiego użytkownika (Bob)** — `POST /api/organizations/{id}/invite`. Ponieważ
   w demo nie skonfigurowano dostawcy e-mail (SendGrid), zaproszenie **nie jest realnie
   wysyłane** — serwis loguje ostrzeżenie zawierające token zaproszenia:

   ```bash
   docker compose logs authservice | grep "Invitation token:" | tail -1
   ```

   Token trzeba ręcznie skopiować z logu.

6. **Rejestracja Boba i akceptacja zaproszenia** — Bob musi zarejestrować się na **ten sam
   e-mail**, na który zaproszenie zostało wysłane, a następnie wywołać
   `POST /api/organizations/invitations/accept` ze skopiowanym tokenem.

7. **Weryfikacja członkostwa** — `GET /api/organizations/{id}` jako Alice, sprawdzenie pola
   `members` — Bob powinien się tam pojawić.

8. **Panel admina** — logowanie jako seedowany `SuperAdmin`, a następnie
   `GET /api/admin/stats` i `GET /api/admin/users` pokazują dane na poziomie administratora.

### Zakończenie demo

```bash
docker compose down -v   # -v usuwa też wolumin Postgresa, czyszcząc dane demo
```

Demo celowo nie konfiguruje SendGrid ani OAuth, żeby dało się je uruchomić offline, w pełni
lokalnie, bez żadnych zewnętrznych kont — jedyny „obejście” to ręczne czytanie tokenu
zaproszenia z logów zamiast z e-maila.

---

## 5. Testy

```bash
dotnet test
```

## 6. Dalsza lektura

- [`README.md`](README.md) — pełna referencja konfiguracji i API.
- [`DEMO.md`](DEMO.md) — surowy skrypt demo opisany w sekcji 4.
- [`EXTRACTION.md`](EXTRACTION.md) — historia i uzasadnienie wydzielenia tego serwisu z
  większego projektu, co zostało zachowane, a co świadomie pominięte.
