using System.Security.Claims;
using IdentityServerPersistence.SystemStores;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.Login;

/// <inheritdoc />
public class EntraIdVerifiedIdentifierEnrollmentService(
    IOctoIdentityProviderStore identityProviderStore,
    IVerifiedIdentifierResolver verifiedIdentifierResolver,
    ILogger<EntraIdVerifiedIdentifierEnrollmentService> logger)
    : IEntraIdVerifiedIdentifierEnrollmentService
{
    /// <summary>
    ///     Azure Entra's object-id claim. Emitted mapped to the long WS-* URI when the OpenIdConnect
    ///     handler maps inbound claims (the default), or as the short <c>oid</c> when it does not —
    ///     both are accepted.
    /// </summary>
    private const string EntraObjectIdClaimUri = "http://schemas.microsoft.com/identity/claims/objectidentifier";

    private const string EntraObjectIdClaimShort = "oid";

    public async Task EnrollFromExternalLoginAsync(RtUser user, string providerName,
        IReadOnlyList<Claim> externalClaims)
    {
        try
        {
            // The scheme name may be prefixed (e.g. "octo:MyEntra"); the provider is stored under the
            // bare name — same normalization the login callback uses.
            var normalizedName = providerName.Contains(':')
                ? providerName.Split(':', 2)[1]
                : providerName;

            var provider = await identityProviderStore.GetByNameAsync(normalizedName);
            if (provider is not RtAzureEntraIdIdentityProvider)
            {
                // Only the EntraID provider auto-enrolls its oid — a Teams sender is an EntraID
                // object id, and no other provider's subject matches it.
                return;
            }

            var objectId = externalClaims.FirstOrDefault(c => c.Type == EntraObjectIdClaimUri)?.Value
                           ?? externalClaims.FirstOrDefault(c => c.Type == EntraObjectIdClaimShort)?.Value;

            if (string.IsNullOrWhiteSpace(objectId))
            {
                logger.LogWarning(
                    "EntraID login for user '{UserName}' via provider '{Provider}' carried no 'oid' claim; " +
                    "cannot enroll the verified EntraID identifier for Teams caller resolution (AB#5124)",
                    user.UserName, normalizedName);
                return;
            }

            // Enrollment trust Strong: an authenticated IdP login is the strongest possible proof
            // that the oid belongs to this user. Source = IdentityProvider marks the provenance.
            // Idempotent upsert — the resolver keeps at most one row per (kind, value) per tenant.
            var bindingRtId = await verifiedIdentifierResolver.StoreBindingAsync(
                new VerifiedIdentifierBinding(
                    RtIdentifierKindEnum.EntraIdObjectId,
                    objectId,
                    user.RtId,
                    RtTrustLevelEnum.Strong,
                    RtIdentifierSourceEnum.IdentityProvider));

            logger.LogInformation(
                "Enrolled verified EntraID identifier {BindingRtId} (oid) for user '{UserName}' via provider '{Provider}' (AB#5124)",
                bindingRtId, user.UserName, normalizedName);
        }
        catch (Exception ex)
        {
            // Best-effort: enrollment is a side effect of login and must never block it. A missing
            // System.Identity model (older tenant) or a transient write error simply means the oid
            // is not enrolled yet — the next login retries the idempotent upsert.
            logger.LogError(ex,
                "Failed to enroll the verified EntraID identifier for user '{UserName}' via provider '{Provider}'; " +
                "login continues, Teams caller resolution may fall back to anonymous (AB#5124)",
                user.UserName, providerName);
        }
    }
}
