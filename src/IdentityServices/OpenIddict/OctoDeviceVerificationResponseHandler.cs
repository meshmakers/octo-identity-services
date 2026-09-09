using System.Text.Json;
using Microsoft.AspNetCore;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Meshmakers.Octo.Backend.IdentityServices.OpenIddict;

/// <summary>
///     Renders the end-user verification response of the device flow as the JSON result DTO the
///     Angular device page expects (<c>{ success, errorMessage }</c> — the former
///     <c>DeviceAuthorizationResultDto</c> contract of <c>DeviceApiController</c>, AB#4993).
///     Without this handler OpenIddict would render its default (browser-oriented) response,
///     which the SPA's XHR cannot consume.
/// </summary>
public class OctoDeviceVerificationResponseHandler
    : IOpenIddictServerHandler<ApplyEndUserVerificationResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyEndUserVerificationResponseContext>()
            .UseSingletonHandler<OctoDeviceVerificationResponseHandler>()
            .SetOrder(int.MinValue + 50_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ApplyEndUserVerificationResponseContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var httpContext = context.Transaction.GetHttpRequest()?.HttpContext;
        if (httpContext == null)
        {
            return;
        }

        var success = string.IsNullOrEmpty(context.Response.Error);
        var payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            success,
            errorMessage = success
                ? null
                : context.Response.ErrorDescription ?? context.Response.Error
        });

        httpContext.Response.StatusCode = StatusCodes.Status200OK;
        httpContext.Response.ContentType = "application/json; charset=utf-8";
        httpContext.Response.ContentLength = payload.Length;
        await httpContext.Response.Body.WriteAsync(payload, httpContext.RequestAborted);

        context.HandleRequest();
    }
}
