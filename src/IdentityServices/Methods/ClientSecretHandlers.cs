using IdentityServerPersistence.Services;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Services.Methods;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>
///     Handler of <c>System.Identity/Client.AddSecret-1</c> (AB#7780): generates a new secret for a confidential client,
///     stores only its hash and returns the clear text exactly once as the (sensitive) result.
/// </summary>
/// <remarks>
///     <para>
///         REST facade (AB#9037): <c>POST system/v1/apiSecrets/client/{clientId}</c> (<c>ApiSecretsController.PostClient</c>).
///         Generator: 32 bytes from the CSPRNG, URL-safe Base64 (<see cref="ClientMirrorSecrets.GenerateSecret" />); stored
///         format <see cref="OctoSecretHasher.HashSecret" /> (Base64 SHA-256, which <see cref="OctoApplicationManager" />
///         validates against every unexpired record of the client); a version-checked write of the client, mirror sync after it.
///     </para>
///     <para>
///         A public client (<c>RequireClientSecret</c> false; it never authenticates with a secret) is refused with
///         <c>CLIENT_SECRET_NOT_REQUIRED</c>, an <c>expirationDate</c> in the past (a secret that could never be used) with
///         <c>METHOD_VALIDATION_FAILED</c>. The record gets <c>Type = SharedSecret</c> (the validation does not filter by type).
///         The description <c>octo:mirror-own-secret</c> is reserved for the mirror machinery (AB#5061) and refused with
///         <c>METHOD_VALIDATION_FAILED</c> (<c>field</c> = <c>description</c>).
///     </para>
/// </remarks>
internal sealed class ClientAddSecretHandler(IServiceProvider services)
    : ClientSecretMethodHandlerBase(services), ICkMethodHandler<ClientAddSecretParameters, ClientAddSecretResult>
{
    public Task<CkMethodOutcome<ClientAddSecretResult>> HandleAsync(
        CkMethodContext<ClientAddSecretParameters> context, CancellationToken cancellationToken) =>
        AuditedAsync(context, async details =>
        {
            var (failure, clearText) = await AddSecretCoreAsync(context.CallerPrincipal, context.TenantId,
                context.TargetRtId, context.Parameters.Description, context.Parameters.ExpirationDate,
                current => current.RequireClientSecret
                    ? null
                    : new CkMethodFailure(ClientSecretMethodErrors.ClientSecretNotRequired),
                null, details, cancellationToken).ConfigureAwait(false);
            return failure != null
                ? CkMethodOutcome<ClientAddSecretResult>.Fail(failure)
                : new ClientAddSecretResult { Value = clearText };
        }, outcome => outcome.Failure?.Code);
}

/// <summary>
///     Handler of <c>System.Identity/Client.RemoveSecret-1</c> (AB#7780): removes a secret of the client. Afterwards the
///     client can no longer authenticate with it.
/// </summary>
/// <remarks>
///     <c>secretValue</c> is either the stored value as the list of secrets shows it (REST facade, AB#9037:
///     <c>POST system/v1/apiSecrets/client/{clientId}/delete</c> and the legacy <c>DELETE .../{secretValue}</c> pass the stored
///     SHA-256 value, because the clear text is shown only once) or the clear text of the secret (hashed and compared like the
///     token endpoint does). Every record that matches is removed. No match is <c>SECRET_NOT_FOUND</c> without any parameter:
///     the answer never echoes the value.
/// </remarks>
internal sealed class ClientRemoveSecretHandler(IServiceProvider services)
    : ClientSecretMethodHandlerBase(services), ICkMethodHandler<ClientRemoveSecretParameters>
{
    public Task<CkMethodOutcome> HandleAsync(CkMethodContext<ClientRemoveSecretParameters> context,
        CancellationToken cancellationToken) =>
        AuditedAsync(context, async details =>
        {
            var failure = await RemoveSecretCoreAsync(context.CallerPrincipal, context.TenantId, context.TargetRtId,
                context.Parameters.SecretValue, null, details, cancellationToken).ConfigureAwait(false);
            return failure != null ? CkMethodOutcome.Fail(failure) : CkMethodOutcome.Ok();
        }, outcome => outcome.Failure?.Code);
}

/// <summary>
///     Handler of <c>System.Identity/Client.UpdateSecret-1</c> (System.Identity 3.4.0, AB#9037): replaces description and
///     expiration date of a secret of the client. REST facade: <c>PUT system/v1/apiSecrets/client/{clientId}</c>.
/// </summary>
/// <remarks>
///     The secret is named like on <c>RemoveSecret</c> (stored value or clear text); the first match is updated, its value and
///     type stay. An omitted description or expiration date is cleared, as the REST <c>PUT</c> replaced both. An expiration in
///     the past is accepted (it retires the secret). No match is <c>SECRET_NOT_FOUND</c>; a write that keeps losing against
///     concurrent writers is <c>CONCURRENT_CHANGE</c>.
/// </remarks>
internal sealed class ClientUpdateSecretHandler(IServiceProvider services)
    : ClientSecretMethodHandlerBase(services), ICkMethodHandler<ClientUpdateSecretParameters>
{
    public Task<CkMethodOutcome> HandleAsync(CkMethodContext<ClientUpdateSecretParameters> context,
        CancellationToken cancellationToken) =>
        AuditedAsync(context, async details =>
        {
            var failure = await UpdateSecretCoreAsync(context.CallerPrincipal, context.TenantId, context.TargetRtId,
                context.Parameters.SecretValue, context.Parameters.Description, context.Parameters.ExpirationDate, details,
                cancellationToken).ConfigureAwait(false);
            return failure != null ? CkMethodOutcome.Fail(failure) : CkMethodOutcome.Ok();
        }, outcome => outcome.Failure?.Code);
}

/// <summary>
///     Handler of <c>System.Identity/ApiResource.AddSecret-1</c> (System.Identity 3.4.0, AB#9037): generates a new
///     (introspection) secret for an API resource, stores only its hash and returns the clear text exactly once. REST facade:
///     <c>POST system/v1/apiSecrets/apiResource/{name}</c>. Same generator, format and rules as <c>Client.AddSecret</c>
///     (expiration in the past and the reserved mirror description refused); an API resource has no public variant.
/// </summary>
internal sealed class ApiResourceAddSecretHandler(IServiceProvider services)
    : ApiResourceSecretMethodHandlerBase(services), ICkMethodHandler<ApiResourceAddSecretParameters, ApiResourceAddSecretResult>
{
    public Task<CkMethodOutcome<ApiResourceAddSecretResult>> HandleAsync(
        CkMethodContext<ApiResourceAddSecretParameters> context, CancellationToken cancellationToken) =>
        AuditedAsync(context, async details =>
        {
            var (failure, clearText) = await AddSecretCoreAsync(context.CallerPrincipal, context.TenantId,
                context.TargetRtId, context.Parameters.Description, context.Parameters.ExpirationDate, null,
                ClientSecretMethodErrors.ConcurrentChange, details, cancellationToken).ConfigureAwait(false);
            return failure != null
                ? CkMethodOutcome<ApiResourceAddSecretResult>.Fail(failure)
                : new ApiResourceAddSecretResult { Value = clearText };
        }, outcome => outcome.Failure?.Code);
}

/// <summary>
///     Handler of <c>System.Identity/ApiResource.RemoveSecret-1</c> (System.Identity 3.4.0, AB#9037), see
///     <see cref="ClientRemoveSecretHandler" />. REST facade: <c>POST system/v1/apiSecrets/apiResource/{name}/delete</c> and the
///     legacy <c>DELETE .../{secretValue}</c>.
/// </summary>
internal sealed class ApiResourceRemoveSecretHandler(IServiceProvider services)
    : ApiResourceSecretMethodHandlerBase(services), ICkMethodHandler<ApiResourceRemoveSecretParameters>
{
    public Task<CkMethodOutcome> HandleAsync(CkMethodContext<ApiResourceRemoveSecretParameters> context,
        CancellationToken cancellationToken) =>
        AuditedAsync(context, async details =>
        {
            var failure = await RemoveSecretCoreAsync(context.CallerPrincipal, context.TenantId, context.TargetRtId,
                context.Parameters.SecretValue, ClientSecretMethodErrors.ConcurrentChange, details, cancellationToken)
                .ConfigureAwait(false);
            return failure != null ? CkMethodOutcome.Fail(failure) : CkMethodOutcome.Ok();
        }, outcome => outcome.Failure?.Code);
}

/// <summary>
///     Handler of <c>System.Identity/ApiResource.UpdateSecret-1</c> (System.Identity 3.4.0, AB#9037), see
///     <see cref="ClientUpdateSecretHandler" />. REST facade: <c>PUT system/v1/apiSecrets/apiResource/{name}</c>.
/// </summary>
internal sealed class ApiResourceUpdateSecretHandler(IServiceProvider services)
    : ApiResourceSecretMethodHandlerBase(services), ICkMethodHandler<ApiResourceUpdateSecretParameters>
{
    public Task<CkMethodOutcome> HandleAsync(CkMethodContext<ApiResourceUpdateSecretParameters> context,
        CancellationToken cancellationToken) =>
        AuditedAsync(context, async details =>
        {
            var failure = await UpdateSecretCoreAsync(context.CallerPrincipal, context.TenantId, context.TargetRtId,
                context.Parameters.SecretValue, context.Parameters.Description, context.Parameters.ExpirationDate, details,
                cancellationToken).ConfigureAwait(false);
            return failure != null ? CkMethodOutcome.Fail(failure) : CkMethodOutcome.Ok();
        }, outcome => outcome.Failure?.Code);
}
