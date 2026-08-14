## What this changes

<!-- One or two sentences. What behaviour is different after this PR? -->

## Why

<!-- Link the issue if there is one. If there isn't, explain the problem this solves. -->

Closes #

## Approach and alternatives

<!--
What you did, and what you considered and rejected. This repository's issues are written
this way; PRs are much easier to review when they match.
-->

## Security impact

<!--
What can an attacker do after this change that they could not before, or what does it stop
them doing? "None — this is a documentation change" is a perfectly good answer.
-->

## Breaking changes

<!--
Any change to a request or response shape, a status code, a default, or a configuration key.
Say what a consumer has to do. "None" if none.
-->

## Schema changes

<!--
If you changed the model: is there matching DDL in docs/schema/upgrade/ for both PostgreSQL
and SQL Server? Existing deployments do not get new columns from EnsureCreated.
-->

## Checklist

- [ ] `dotnet build AuthService.sln` passes
- [ ] `dotnet test AuthService.sln` passes
- [ ] `dotnet format --verify-no-changes` passes
- [ ] Behaviour changes are covered by a test
- [ ] Documentation updated (README / docs/) where the change is user-visible
