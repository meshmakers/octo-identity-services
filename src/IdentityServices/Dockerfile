FROM meshmakers/dotnet_aspnetcore-runtime-node:1.2.5.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM meshmakers/dotnet_sdk-node:1.2.5.0 AS build

ARG OCTO_PRIVATE_NUGET_SERVICE
ARG OCTO_PRIVATE_NUGET_CERTIFICATE
ARG OCTO_VERSION
# AB#4209 Step 4 PR 1 — accept the hotfix-train lib/comm version split so the
# CI pipeline variables (OctoCoreLibVersion / OctoCommVersion, set in
# pipeline-templates tpl-v0.4.7 update-build-number.yml on non-r-tag branches)
# can flow into the in-container `dotnet build`. Without these the
# Directory.Build.props condition `OctoCoreLibVersion==''` matches and falls
# through to the explicit hardcoded pin (post-b510924), which on main / PR
# builds resolves to a public-feed version that may not yet carry source-side
# additions (e.g. MsBuildTasks WrapScalarInRecord schema from Engine #194).
# Surfaced by PR #102 build #35925.
ARG OCTO_CORE_LIB_VERSION
ARG OCTO_COMM_VERSION

COPY ${OCTO_PRIVATE_NUGET_CERTIFICATE} /usr/local/share/ca-certificates/nugetca.crt
RUN chmod 644 /usr/local/share/ca-certificates/nugetca.crt && update-ca-certificates

WORKDIR /src
COPY . .
ENV NUGET_XMLDOC_MODE=none
WORKDIR "/src/src/IdentityServices"
RUN dotnet build "IdentityServices.csproj" -c Release \
    -p:OctoNugetPrivateServer=${OCTO_PRIVATE_NUGET_SERVICE} \
    ${OCTO_VERSION:+-p:OctoVersion=${OCTO_VERSION}} \
    ${OCTO_CORE_LIB_VERSION:+-p:OctoCoreLibVersion=${OCTO_CORE_LIB_VERSION}} \
    ${OCTO_COMM_VERSION:+-p:OctoCommVersion=${OCTO_COMM_VERSION}}

FROM build AS publish
RUN dotnet publish "IdentityServices.csproj" -c Release \
    -p:OctoNugetPrivateServer=${OCTO_PRIVATE_NUGET_SERVICE} \
    ${OCTO_VERSION:+-p:OctoVersion=${OCTO_VERSION}} \
    ${OCTO_CORE_LIB_VERSION:+-p:OctoCoreLibVersion=${OCTO_CORE_LIB_VERSION}} \
    ${OCTO_COMM_VERSION:+-p:OctoCommVersion=${OCTO_COMM_VERSION}} \
    -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
COPY --from=build /src/src/IdentityServices/run.sh /app/run.sh

ENTRYPOINT ["/bin/sh", "-c", "chmod +x /app/run.sh && /app/run.sh"]