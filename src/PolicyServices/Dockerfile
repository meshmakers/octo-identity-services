FROM mcr.microsoft.com/dotnet/aspnet:8.0-bookworm-slim AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:8.0-bookworm-slim AS build

ARG OCTO_PRIVATE_NUGET_SERVICE
ARG OCTO_PRIVATE_NUGET_CERTIFICATE

COPY ${OCTO_PRIVATE_NUGET_CERTIFICATE} /usr/local/share/ca-certificates/nugetca.crt
RUN chmod 644 /usr/local/share/ca-certificates/nugetca.crt && update-ca-certificates

RUN wget http://crt.sectigo.com/SectigoPublicCodeSigningRootR46.p7c -O sectigo.p7c && \
    openssl pkcs7 -inform DER -outform PEM -in sectigo.p7c -print_certs -out sectigo.pem && \
    cat sectigo.pem >> /usr/share/dotnet/sdk/8.0.303/trustedroots/codesignctl.pem && \
    rm -v sectigo.p7c sectigo.pem

WORKDIR /src
COPY . .
ENV NUGET_XMLDOC_MODE=none
WORKDIR "/src/src/PolicyServices"
RUN dotnet build "PolicyServices.csproj" -c Release -p:OctoNugetPrivateServer=${OCTO_PRIVATE_NUGET_SERVICE}

FROM build AS publish
RUN dotnet publish "PolicyServices.csproj" -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "Meshmakers.Octo.Backend.PolicyServices.dll"]