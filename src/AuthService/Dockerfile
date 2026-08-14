# Production Dockerfile for AuthService
# Multi-stage build for an optimized production image

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 8080

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Copy project file for restore
COPY src/AuthService/AuthService.csproj src/AuthService/

RUN dotnet restore src/AuthService/AuthService.csproj

# Copy source code
COPY src/AuthService/ src/AuthService/

# Publish
WORKDIR /src/src/AuthService
RUN dotnet publish -c Release -o /app/publish --no-restore /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .
ENV ASPNETCORE_URLS=http://+:8080
ENTRYPOINT ["dotnet", "AuthService.dll"]
