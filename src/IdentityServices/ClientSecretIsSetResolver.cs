using AutoMapper;
using Meshmakers.Octo.Backend.Authentication.Secrets;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices;

/// <summary>
///     Maps <c>ClientSecretIsSet</c> of the external identity-provider DTOs from the stored form of the
///     <c>ClientSecret</c> only — the value is never decrypted for it (AB#5540): a protected envelope
///     whose key is in the key ring, a non-empty legacy value (clear text / <c>enc:v1</c> before the
///     encrypt sweep) or a non-empty pending value (just written) count as set. An envelope whose key
///     id is not in the key ring reads as not set (decision r2-2: kept stored, needs the key or a
///     re-entry).
/// </summary>
public sealed class ClientSecretIsSetResolver(IIdentityProviderSecretReader secretReader)
    : IValueResolver<RtIdentityProvider, IdentityProviderDto, bool?>
{
    /// <inheritdoc />
    public bool? Resolve(RtIdentityProvider source, IdentityProviderDto destination, bool? destMember,
        ResolutionContext context)
        => secretReader.GetClientSecretState(source) == IdentityProviderSecretState.Set;
}
