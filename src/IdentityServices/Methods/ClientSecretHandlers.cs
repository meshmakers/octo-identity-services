using IdentityServerPersistence.Services;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Methods;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>
///     Handler of <c>System.Identity/Client.AddSecret-1</c> (AB#7780): generates a new secret for a confidential client,
///     stores only its hash and returns the clear text exactly once as the (sensitive) result.
/// </summary>
/// <remarks>
///     <para>
///         REST parity: <c>POST system/v1/apiSecrets/client/{clientId}</c> (<c>ApiSecretsController.PostClient</c>), same
///         generator (32 bytes from the CSPRNG, URL-safe Base64, <see cref="ClientMirrorSecrets.GenerateSecret" />), same
///         stored format (<see cref="OctoSecretHasher.HashSecret" />: Base64 SHA-256, which <see cref="OctoApplicationManager" />
///         validates against every unexpired record of the client), same store write (incl. mirror sync).
///     </para>
///     <para>
///         Stricter than REST, never more: a public client (<c>RequireClientSecret</c> false; it never authenticates with a
///         secret) is refused with <c>CLIENT_SECRET_NOT_REQUIRED</c>, and an <c>expirationDate</c> in the past (a secret that
///         could never be used) with <c>METHOD_VALIDATION_FAILED</c>. The record gets <c>Type = SharedSecret</c> (REST leaves
///         it empty; the validation does not filter by type).
///     </para>
/// </remarks>
internal sealed class ClientAddSecretHandler(IServiceProvider services)
    : ClientSecretMethodHandlerBase(services), ICkMethodHandler<ClientAddSecretParameters, ClientAddSecretResult>
{
    public async Task<CkMethodOutcome<ClientAddSecretResult>> HandleAsync(
        CkMethodContext<ClientAddSecretParameters> context, CancellationToken cancellationToken)
    {
        var details = new Dictionary<string, string>(StringComparer.Ordinal);
        var outcomeCode = "METHOD_HANDLER_FAILED";
        try
        {
            var outcome = await AddAsync(context, details).ConfigureAwait(false);
            outcomeCode = outcome.Failure?.Code ?? IdentityMethodAuditWriter.SuccessOutcome;
            return outcome;
        }
        finally
        {
            // One audit record per call, also when the call throws (the host answers METHOD_HANDLER_FAILED then).
            await AuditAsync(context, outcomeCode, details).ConfigureAwait(false);
        }
    }

    private async Task<CkMethodOutcome<ClientAddSecretResult>> AddAsync(
        CkMethodContext<ClientAddSecretParameters> context, Dictionary<string, string> details)
    {
        var (failure, client) = await ResolveTargetAsync(context.CallerPrincipal, context.TenantId, context.TargetRtId,
            details).ConfigureAwait(false);
        if (failure != null)
        {
            return CkMethodOutcome<ClientAddSecretResult>.Fail(failure);
        }

        if (!client!.RequireClientSecret)
        {
            return CkMethodOutcome<ClientAddSecretResult>.Fail(ClientSecretMethodErrors.ClientSecretNotRequired);
        }

        DateTime? expiration = context.Parameters.ExpirationDate?.ToUniversalTime();
        if (expiration != null && expiration <= DateTime.UtcNow)
        {
            return CkMethodOutcome<ClientAddSecretResult>.ValidationFailed("expirationDate", "in-the-past");
        }

        var clearText = ClientMirrorSecrets.GenerateSecret();
        client.ClientSecrets ??= new AttributeRecordValueList<RtSecretRecord>();
        client.ClientSecrets.Add(new RtSecretRecord
        {
            Type = ClientMirrorSecrets.SharedSecretType,
            Value = OctoSecretHasher.HashSecret(clearText),
            Description = context.Parameters.Description,
            ExpirationDateTime = expiration
        });

        await SaveAsync(client, details).ConfigureAwait(false);
        return new ClientAddSecretResult { Value = clearText };
    }
}

/// <summary>
///     Handler of <c>System.Identity/Client.RemoveSecret-1</c> (AB#7780): removes a secret of the client. Afterwards the
///     client can no longer authenticate with it.
/// </summary>
/// <remarks>
///     <c>secretValue</c> is either the stored value as the list of secrets shows it (REST parity:
///     <c>DELETE system/v1/apiSecrets/client/{clientId}/{secretValue}</c> takes the stored SHA-256 value, because the clear
///     text is shown only once) or the clear text of the secret (hashed and compared like the token endpoint does). Every record
///     that matches is removed, as in REST. No match is <c>SECRET_NOT_FOUND</c> without any parameter: unlike REST, the answer
///     never echoes the value.
/// </remarks>
internal sealed class ClientRemoveSecretHandler(IServiceProvider services)
    : ClientSecretMethodHandlerBase(services), ICkMethodHandler<ClientRemoveSecretParameters>
{
    /// <summary>Audit detail: number of secret records the call removed.</summary>
    internal const string RemovedCountDetail = "removedCount";

    public async Task<CkMethodOutcome> HandleAsync(CkMethodContext<ClientRemoveSecretParameters> context,
        CancellationToken cancellationToken)
    {
        var details = new Dictionary<string, string>(StringComparer.Ordinal);
        var outcomeCode = "METHOD_HANDLER_FAILED";
        try
        {
            var outcome = await RemoveAsync(context, details).ConfigureAwait(false);
            outcomeCode = outcome.Failure?.Code ?? IdentityMethodAuditWriter.SuccessOutcome;
            return outcome;
        }
        finally
        {
            await AuditAsync(context, outcomeCode, details).ConfigureAwait(false);
        }
    }

    private async Task<CkMethodOutcome> RemoveAsync(CkMethodContext<ClientRemoveSecretParameters> context,
        Dictionary<string, string> details)
    {
        var (failure, client) = await ResolveTargetAsync(context.CallerPrincipal, context.TenantId, context.TargetRtId,
            details).ConfigureAwait(false);
        if (failure != null)
        {
            return CkMethodOutcome.Fail(failure);
        }

        var secretValue = context.Parameters.SecretValue;
        if (string.IsNullOrEmpty(secretValue))
        {
            return CkMethodOutcome.ValidationFailed("secretValue", "required");
        }

        // RemoveAll with a predicate: the list hands out wrapper instances of the stored records, so a Remove by instance
        // does not find a record that was read from the database.
        var removed = client!.ClientSecrets?.RemoveAll(s => Matches(s, secretValue)) ?? 0;
        details[RemovedCountDetail] = removed.ToString(System.Globalization.CultureInfo.InvariantCulture);
        if (removed == 0)
        {
            return CkMethodOutcome.Fail(ClientSecretMethodErrors.SecretNotFound);
        }

        await SaveAsync(client, details).ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }

    /// <summary>The stored value as listed, or the clear text hashed as the token endpoint does (fixed-time compare).</summary>
    private static bool Matches(RtSecretRecord secret, string secretValue) =>
        !string.IsNullOrEmpty(secret.Value) &&
        (string.Equals(secret.Value, secretValue, StringComparison.Ordinal) ||
         OctoSecretHasher.Matches(secretValue, secret.Value));
}
