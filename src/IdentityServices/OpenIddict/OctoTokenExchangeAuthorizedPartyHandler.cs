using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Meshmakers.Octo.Backend.IdentityServices.OpenIddict;

/// <summary>
///     Replaces the built-in <c>Exchange.ValidateAuthorizedParty</c> handler. The built-in
///     requires the exchanging client to be an audience or presenter of the subject token
///     (rejecting with ID2186/ID2187 otherwise); platform access tokens deliberately carry no
///     presenter claims (pre-migration wire format) and their audiences are API resources, never
///     client ids — so every RFC 8693 cross-tenant exchange would fail at the HTTP layer before
///     <see cref="TenantExchangeProcessor" /> runs. That processor owns the actual authorization
///     rules (signature validation, user+tenant claims, ancestor check, fail-closed acr assert).
///     For every other grant (authorization_code, refresh_token, device_code) the built-in checks
///     are preserved by delegating to the original handler.
/// </summary>
public class OctoTokenExchangeAuthorizedPartyHandler
    : IOpenIddictServerHandler<ValidateTokenRequestContext>
{
    private static readonly OpenIddictServerHandlers.Exchange.ValidateAuthorizedParty Inner = new();

    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
            .UseSingletonHandler<OctoTokenExchangeAuthorizedPartyHandler>()
            .SetOrder(OpenIddictServerHandlers.Exchange.ValidateAuthorizedParty.Descriptor.Order)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ValidateTokenRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.Request.IsTokenExchangeGrantType()
            ? default
            : Inner.HandleAsync(context);
    }
}
