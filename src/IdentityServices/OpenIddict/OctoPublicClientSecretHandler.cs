using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Meshmakers.Octo.Backend.IdentityServices.OpenIddict;

/// <summary>
///     Duende parity: clients with <c>RequireClientSecret = false</c> (mapped to the OpenIddict
///     public client type) may still send a <c>client_secret</c> — Duende silently ignored it,
///     while OpenIddict rejects the request with <c>invalid_client</c> (ID2053). Deployed
///     consumers (octo-cli, adapters) do send a secret for such clients, so the server must
///     stay lenient: this handler drops the secret before the built-in
///     <c>ValidateClientType</c> check runs.
/// </summary>
public class OctoPublicClientSecretHandler(IOpenIddictApplicationManager applicationManager,
    ILogger<OctoPublicClientSecretHandler> logger)
    : IOpenIddictServerHandler<ProcessAuthenticationContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
            .UseScopedHandler<OctoPublicClientSecretHandler>()
            .SetOrder(OpenIddictServerHandlers.ValidateClientType.Descriptor.Order - 1)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ProcessAuthenticationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Request == null
            || string.IsNullOrEmpty(context.Request.ClientId)
            || string.IsNullOrEmpty(context.Request.ClientSecret))
        {
            return;
        }

        var application = await applicationManager.FindByClientIdAsync(
            context.Request.ClientId, context.CancellationToken);
        if (application == null)
        {
            return;
        }

        var clientType = await applicationManager.GetClientTypeAsync(
            application, context.CancellationToken);
        if (string.Equals(clientType, ClientTypes.Public, StringComparison.OrdinalIgnoreCase))
        {
            logger.LogDebug(
                "Ignoring client_secret sent by public client '{ClientId}' (Duende parity)",
                context.Request.ClientId);
            context.Request.ClientSecret = null;
        }
    }
}
