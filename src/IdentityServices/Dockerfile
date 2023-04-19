FROM mcr.microsoft.com/dotnet/aspnet:7.0-bullseye-slim AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0-bullseye-slim AS build
WORKDIR /src
COPY . .
WORKDIR "/src/src/Backend/IdentityServices"
RUN dotnet build "IdentityServices.csproj" -c Release

FROM build AS publish
RUN dotnet publish "IdentityServices.csproj" -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
COPY --from=build /src/src/Backend/IdentityServices/run.sh /app/run.sh

ENTRYPOINT ["/bin/sh", "-c", "chmod +x /app/run.sh && /app/run.sh"]