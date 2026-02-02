FROM meshmakers/dotnet_aspnetcore-runtime-node:1.2.1.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM meshmakers/dotnet_sdk-node:1.2.1.0 AS build

ARG OCTO_PRIVATE_NUGET_SERVICE
ARG OCTO_PRIVATE_NUGET_CERTIFICATE
ARG OCTO_VERSION

COPY ${OCTO_PRIVATE_NUGET_CERTIFICATE} /usr/local/share/ca-certificates/nugetca.crt
RUN chmod 644 /usr/local/share/ca-certificates/nugetca.crt && update-ca-certificates

WORKDIR /src
COPY . .
ENV NUGET_XMLDOC_MODE=none
WORKDIR "/src/src/IdentityServices"
RUN dotnet build "IdentityServices.csproj" -c Release -p:OctoNugetPrivateServer=${OCTO_PRIVATE_NUGET_SERVICE} -p:OctoVersion=${OCTO_VERSION}

FROM build AS publish
RUN dotnet publish "IdentityServices.csproj" -c Release -p:OctoNugetPrivateServer=${OCTO_PRIVATE_NUGET_SERVICE} -p:OctoVersion=${OCTO_VERSION} -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
COPY --from=build /src/src/IdentityServices/run.sh /app/run.sh

ENTRYPOINT ["/bin/sh", "-c", "chmod +x /app/run.sh && /app/run.sh"]