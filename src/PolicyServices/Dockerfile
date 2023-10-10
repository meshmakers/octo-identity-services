FROM mcr.microsoft.com/dotnet/aspnet AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk AS build
WORKDIR /src
COPY . .
WORKDIR "/src/src/PolicyServices"
RUN dotnet build "PolicyServices.csproj" -c Release 

FROM build AS publish
RUN dotnet publish "PolicyServices.csproj" -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "Meshmakers.Octo.Backend.PolicyServices.dll"]