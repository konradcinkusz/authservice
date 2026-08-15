# Production Dockerfile for AuthService
# Multi-stage build for an optimized production image

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS base
WORKDIR /app
EXPOSE 8080

# Pinned to the *build* platform rather than the target: emulating an SDK build under QEMU to
# produce an arm64 image takes an order of magnitude longer than cross-compiling with -a.
FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG TARGETARCH
WORKDIR /src

# Copy project files for restore. AuthService references AuthService.Data and both migration
# assemblies, so restore needs all four to resolve the graph.
COPY src/AuthService/AuthService.csproj src/AuthService/
COPY src/AuthService.Data/AuthService.Data.csproj src/AuthService.Data/
COPY src/AuthService.Migrations.PostgreSQL/AuthService.Migrations.PostgreSQL.csproj src/AuthService.Migrations.PostgreSQL/
COPY src/AuthService.Migrations.SqlServer/AuthService.Migrations.SqlServer.csproj src/AuthService.Migrations.SqlServer/

RUN dotnet restore src/AuthService/AuthService.csproj -a "$TARGETARCH"

# Copy source code
COPY src/ src/

# Publish
WORKDIR /src/src/AuthService
RUN dotnet publish -c Release -a "$TARGETARCH" -o /app/publish --no-restore /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .
ENV ASPNETCORE_URLS=http://+:8080
ENTRYPOINT ["dotnet", "AuthService.dll"]
