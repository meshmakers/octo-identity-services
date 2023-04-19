FROM mcr.microsoft.com/dotnet/aspnet:7.0-bullseye-slim AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0-bullseye-slim AS build
WORKDIR /src
COPY . .
WORKDIR "/src/src/Backend/PolicyServices"
RUN dotnet build "PolicyServices.csproj" -c Release 

FROM build AS publish
RUN dotnet publish "PolicyServices.csproj" -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "Meshmakers.Octo.Backend.PolicyServices.dll"]