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
WORKDIR "/src/src/IdentityServices"
RUN dotnet build "IdentityServices.csproj" -c Release -p:OctoNugetPrivateServer=${OCTO_PRIVATE_NUGET_SERVICE}

FROM build AS publish
RUN dotnet publish "IdentityServices.csproj" -c Release -p:OctoNugetPrivateServer=${OCTO_PRIVATE_NUGET_SERVICE} -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
COPY --from=build /src/src/IdentityServices/run.sh /app/run.sh

ENTRYPOINT ["/bin/sh", "-c", "chmod +x /app/run.sh && /app/run.sh"]