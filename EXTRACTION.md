# Extraction notes

This service was extracted from the `AureliusPromptus.AuthService` project in the
[AureliusPromptus](https://github.com/konradcinkusz/aureliuspromptus) monorepo.
`aureliuspromptus` itself was not modified — all work happened only in this repository.

## Was extraction feasible?

Yes. The source `AuthService` was already a self-contained ASP.NET Core project with its
own `DbContext`, its own ASP.NET Identity setup, and only one internal dependency: a
small shared `ServiceDefaults` project providing CORS/database-provider helpers. Those
helpers were reimplemented locally (`Extensions/CorsExtensions.cs`,
`Extensions/DatabaseProviderExtensions.cs`) so this repository has zero dependency on the
source monorepo.

## What was kept (generic auth concerns)

- ASP.NET Core Identity: registration, login, password reset/change, lockout.
- JWT access tokens + server-side revocable refresh tokens.
- OAuth social login (Google, GitHub), enabled conditionally by configuration.
- Multi-tenant **Organizations** with `Owner`/`Admin`/`Member` roles, email invitations
  with retry/backoff tracking, and soft-delete/restore.
- An **Admin API** for user/organization management, role assignment, and lockout control.
- Versioned **consent tracking** (Terms/Privacy/Cookies) for GDPR-style accountability.
- Rate limiting, CORS, Swagger with JWT bearer auth, dual PostgreSQL/SQL Server support.

## What was dropped (product-specific concerns)

These lived in the same ASP.NET Core project as the auth code in the source repo, but
they're billing/product features, not auth — keeping them would have made this "generic
auth service" unusable by anyone who isn't also running that exact product's billing
stack:

- **Notepads** (`NotepadsController`, `Notepad` model, `NotepadPathValidator`) — a
  note-taking product feature with no relationship to authentication.
- **PayPro / Stripe billing** (`PayProController`, `PayProMORService`,
  `StripeSubscription`, `SubscriptionExpirationService`) — a specific payment provider
  integration.
- **Usage quotas** (`QuotaService`, `UserQuota`, `PremiumUsage`, the
  `IWorkspaceOwnershipService` org-count limiter) — subscription-tier gating logic tied
  to the dropped billing system.
- **System messages** (`SystemMessageService`, `UserSystemMessageDismissal`) — in-app
  announcement banners.
- **`SubscriptionType` on `ApplicationUser`** and the JWT claim derived from it, plus the
  `/subscription`, `/quota`, `/usage` endpoints on `AuthController` and the equivalent
  subscription/quota fields on the Admin API.
- **OpenIddict** — configured in the source `Program.cs` but never actually exercised;
  all real token issuance went through the custom JWT `TokenService`. Removed to avoid
  shipping an unused OAuth2/OIDC server surface.
- **Aspire / Azure-specific wiring** (Aspire service defaults, Azure Container Apps
  templates, Key Vault/managed-identity connection strings, the Fly.io `.flycast`
  hostname rewrite) — deployment infrastructure specific to that product's cloud setup.
- **Demo/dev seed data** (hard-coded test users and organizations in `DbSeeder`) —
  replaced with just role seeding plus an optional configuration-driven initial admin.

## Naming changes

The source model classes were already mid-rename from `Organization*` to `Workspace*`
(the C# class names said `Workspace` while the files were still named `Organization*.cs`).
This repository settles on `Organization` consistently — class names, file names, routes,
and DTOs — since that's the more common term for this concept in multi-tenant SaaS auth
services.
