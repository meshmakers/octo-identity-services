using System.Text.Json;
using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Microsoft.AspNetCore.Http;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace IdentityServices.UnitTests.OpenIddict;

/// <summary>
///     AB#7090: the JSON body of the end-user verification response is the contract between
///     <c>DeviceVerificationController</c> and the Angular device page
///     (<c>DeviceAuthorizationResult</c> in <c>consent.models.ts</c>).
/// </summary>
public class OctoDeviceVerificationResponseHandlerTests
{
    private static async Task<(DefaultHttpContext Http, JsonElement Body, ApplyEndUserVerificationResponseContext Ctx)>
        RunAsync(OpenIddictResponse response)
    {
        var http = new DefaultHttpContext();
        http.Response.Body = new MemoryStream();

        var transaction = new OpenIddictServerTransaction
        {
            Response = response
        };
        // OpenIddict keeps the request as a weak reference under the type's full name.
        transaction.Properties[typeof(HttpRequest).FullName!] = new WeakReference<HttpRequest>(http.Request);
        var ctx = new ApplyEndUserVerificationResponseContext(transaction);

        await new OctoDeviceVerificationResponseHandler().HandleAsync(ctx);

        ctx.IsRequestHandled.Should().BeTrue("the handler must find the HttpRequest in the transaction");
        http.Response.Body.Position = 0;
        var body = await JsonDocument.ParseAsync(http.Response.Body,
            cancellationToken: TestContext.Current.CancellationToken);
        return (http, body.RootElement.Clone(), ctx);
    }

    [Fact]
    public async Task Success_IsHttp200_WithSuccessTrue_AndNoError()
    {
        var (http, body, ctx) = await RunAsync(new OpenIddictResponse());

        http.Response.StatusCode.Should().Be(200);
        http.Response.ContentType.Should().StartWith("application/json");
        body.GetProperty("success").GetBoolean().Should().BeTrue();
        body.GetProperty("errorMessage").ValueKind.Should().Be(JsonValueKind.Null);
        body.GetProperty("error").ValueKind.Should().Be(JsonValueKind.Null);
        ctx.IsRequestHandled.Should().BeTrue();
    }

    [Theory]
    [InlineData(OpenIddictConstants.Errors.InvalidToken, "Invalid or expired device code")]
    [InlineData(OpenIddictConstants.Errors.AccessDenied, "The device authorization was denied.")]
    public async Task Failure_IsHttp200_WithSuccessFalse_ErrorCode_AndMessage(string error, string description)
    {
        var (http, body, _) = await RunAsync(new OpenIddictResponse
        {
            Error = error,
            ErrorDescription = description
        });

        http.Response.StatusCode.Should().Be(200);
        body.GetProperty("success").GetBoolean().Should().BeFalse();
        body.GetProperty("error").GetString().Should().Be(error);
        body.GetProperty("errorMessage").GetString().Should().Be(description);
    }
}
