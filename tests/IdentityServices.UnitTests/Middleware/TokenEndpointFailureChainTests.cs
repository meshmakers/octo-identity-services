using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Middleware;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
using MongoDB.Driver.Core.Clusters;
using MongoDB.Driver.Core.Connections;
using MongoDB.Driver.Core.Servers;
using NSubstitute;
using Xunit;

namespace IdentityServices.UnitTests.Middleware;

/// <summary>
///     AB#8177 round 4: both middlewares chained exactly as in Program.cs. <c>OidcTenantResolutionMiddleware</c>
///     buffers the response body of <c>/connect/token</c>; when the inner pipeline threw, the buffer was disposed
///     but <c>Response.Body</c> still pointed to it, so the outer <c>TokenEndpointDatabaseFailureMiddleware</c> hit
///     <c>ObjectDisposedException</c> and the client got a 500 with an empty body instead of the 503.
/// </summary>
public class TokenEndpointFailureChainTests
{
    private static MongoCommandException Unauthorized() =>
        new(new ConnectionId(new ServerId(new ClusterId(1), new DnsEndPoint("localhost", 27017))),
            "Command find requires authentication",
            new MongoDB.Bson.BsonDocument(), new MongoDB.Bson.BsonDocument { { "code", 13 } });

    private static async Task<(DefaultHttpContext Context, MemoryStream Body)> RunAsync(RequestDelegate inner)
    {
        var tenantRepository = Substitute.For<ITenantRepository>();
        tenantRepository.TenantId.Returns("scratch");
        var systemContext = Substitute.For<ISystemContext>();
        systemContext.TryFindTenantRepositoryAsync("scratch").Returns(Task.FromResult<ITenantRepository?>(tenantRepository));

        var services = new ServiceCollection().AddSingleton(systemContext).BuildServiceProvider();

        var oidc = new OidcTenantResolutionMiddleware(
            inner,
            NullLogger<OidcTenantResolutionMiddleware>.Instance,
            Options.Create(new OctoSystemConfiguration()));
        var outer = new TokenEndpointDatabaseFailureMiddleware(
            oidc.InvokeAsync,
            NullLogger<TokenEndpointDatabaseFailureMiddleware>.Instance);

        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.Method = "POST";
        context.Request.Path = "/connect/token";
        context.Request.ContentType = "application/x-www-form-urlencoded";
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("grant_type=client_credentials&acr_values=tenant%3Ascratch"));
        var body = new MemoryStream();
        context.Response.Body = body;

        await outer.InvokeAsync(context);
        return (context, body);
    }

    [Fact]
    public async Task DatabaseFailureInsideTheBufferedTokenPipeline_StillAnswersTheClear503()
    {
        var (context, body) = await RunAsync(_ => throw Unauthorized());

        context.Response.StatusCode.Should().Be(StatusCodes.Status503ServiceUnavailable);
        context.Response.Headers.RetryAfter.ToString().Should().Be("60");
        context.Response.Body.Should().BeSameAs(body, "the original body must be restored");
        body.Position = 0;
        using var json = JsonDocument.Parse(body);
        json.RootElement.GetProperty("error").GetString().Should().Be("temporarily_unavailable");
        json.RootElement.GetProperty("error_description").GetString().Should().Contain("'scratch'");
    }

    [Fact]
    public async Task PartiallyBufferedOutput_IsNotLeakedWhenTheInnerPipelineFails()
    {
        var (context, body) = await RunAsync(async ctx =>
        {
            await ctx.Response.WriteAsync("partial garbage");
            throw Unauthorized();
        });

        context.Response.StatusCode.Should().Be(StatusCodes.Status503ServiceUnavailable);
        body.Position = 0;
        (await new StreamReader(body).ReadToEndAsync(TestContext.Current.CancellationToken)).Should().NotContain("partial garbage");
    }

    [Fact]
    public async Task SuccessfulTokenResponse_IsStillCopiedToTheOriginalBody()
    {
        var (context, body) = await RunAsync(async ctx =>
        {
            ctx.Response.StatusCode = StatusCodes.Status200OK;
            await ctx.Response.WriteAsync("{\"access_token\":\"x\"}");
        });

        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK);
        context.Response.Body.Should().BeSameAs(body);
        body.Position = 0;
        (await new StreamReader(body).ReadToEndAsync(TestContext.Current.CancellationToken)).Should().Be("{\"access_token\":\"x\"}");
    }
}
