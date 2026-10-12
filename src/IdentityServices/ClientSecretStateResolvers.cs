using AutoMapper;
using Meshmakers.Octo.Backend.Authentication.Secrets;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices;

/// <summary>
///     Maps <c>ClientSecretKeyMissing</c> of the external identity-provider DTOs (AB#5540, contract §8):
///     <c>true</c> when a client secret is stored encrypted with a key id that is not in this
///     environment's key ring (e.g. after a restore from another environment) — the ciphertext is kept
///     and the secret needs a re-entry or the key. Determined from the stored form only, never decrypted.
/// </summary>
public sealed class ClientSecretKeyMissingResolver(IIdentityProviderSecretReader secretReader)
    : IValueResolver<RtIdentityProvider, IdentityProviderDto, bool?>
{
    /// <inheritdoc />
    public bool? Resolve(RtIdentityProvider source, IdentityProviderDto destination, bool? destMember,
        ResolutionContext context)
        => secretReader.DescribeClientSecret(source).KeyMissing;
}

/// <summary>
///     Maps <c>ClientSecretSetAt</c> of the external identity-provider DTOs (AB#5540, contract §8): when
///     the stored client secret was set (UTC, <c>RtSecretValue.SetAt</c>); <c>null</c> for a secret set
///     before this feature (legacy) or when none is stored. Never decrypts the value.
/// </summary>
public sealed class ClientSecretSetAtResolver(IIdentityProviderSecretReader secretReader)
    : IValueResolver<RtIdentityProvider, IdentityProviderDto, DateTime?>
{
    /// <inheritdoc />
    public DateTime? Resolve(RtIdentityProvider source, IdentityProviderDto destination, DateTime? destMember,
        ResolutionContext context)
        => secretReader.DescribeClientSecret(source).SetAt;
}
