using System.Net;
using System.Text.Json;
using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Middleware;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using MongoDB.Driver;
using MongoDB.Driver.Core.Clusters;
using MongoDB.Driver.Core.Connections;
using MongoDB.Driver.Core.Servers;
using NSubstitute;
using Xunit;

namespace IdentityServices.UnitTests.Middleware;

/// <summary>
///     AB#8177: a token request that needs an unreachable tenant database answered an unhandled 500 (errorCode 13),
///     which octo-cli showed as "the identity service could not be reached". It now answers a clear OAuth error.
/// </summary>
public class TokenEndpointDatabaseFailureMiddlewareTests
{
    private static MongoCommandException Unauthorized() =>
        new(new ConnectionId(new ServerId(new ClusterId(1), new DnsEndPoint("localhost", 27017))),
            "Command find requires authentication",
            new MongoDB.Bson.BsonDocument(), new MongoDB.Bson.BsonDocument { { "code", 13 } });

    private static (DefaultHttpContext Context, MemoryStream Body) NewContext(string path, ISystemContext? systemContext = null)
    {
        var services = new ServiceCollection();
        if (systemContext != null)
        {
            services.AddSingleton(systemContext);
        }

        var context = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
        context.Request.Path = path;
        context.Items[InfrastructureCommon.TenantIdName] = "scratch";
        var body = new MemoryStream();
        context.Response.Body = body;
        return (context, body);
    }

    private static TokenEndpointDatabaseFailureMiddleware Sut(RequestDelegate next) =>
        new(next, NullLogger<TokenEndpointDatabaseFailureMiddleware>.Instance);

    [Fact]
    public async Task ADatabaseFailureOnTheTokenEndpoint_AnswersAClear503OAuthError()
    {
        var systemContext = Substitute.For<ISystemContext>();
        var (context, body) = NewContext("/connect/token", systemContext);

        await Sut(_ => throw Unauthorized()).InvokeAsync(context);

        context.Response.StatusCode.Should().Be(StatusCodes.Status503ServiceUnavailable);
        context.Response.ContentType.Should().Be("application/json");
        body.Position = 0;
        using var json = JsonDocument.Parse(body);
        json.RootElement.GetProperty("error").GetString().Should().Be("temporarily_unavailable");
        json.RootElement.GetProperty("error_description").GetString().Should()
            .Contain("'scratch'").And.Contain("MongoDB rejected the credentials");
    }

    [Fact]
    public async Task ATimeoutOnTheTokenEndpoint_IsAlsoAClear503()
    {
        var (context, _) = NewContext("/connect/token");

        await Sut(_ => throw new TimeoutException()).InvokeAsync(context);

        context.Response.StatusCode.Should().Be(StatusCodes.Status503ServiceUnavailable);
    }

    [Fact]
    public async Task AFailureInsideTheTenantLookup_IsAlsoAClear503_WithoutATenantName()
    {
        // The middleware wraps the tenant resolution: the tenant is not known yet when its lookup throws.
        var systemContext = Substitute.For<ISystemContext>();
        var (context, body) = NewContext("/connect/token", systemContext);
        context.Items.Remove(InfrastructureCommon.TenantIdName);

        await Sut(_ => throw Unauthorized()).InvokeAsync(context);

        context.Response.StatusCode.Should().Be(StatusCodes.Status503ServiceUnavailable);
        body.Position = 0;
        using var json = JsonDocument.Parse(body);
        json.RootElement.GetProperty("error_description").GetString().Should().Contain("this token request");
        await systemContext.DidNotReceive().EnsureTenantDatabaseUserAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task OtherExceptionsStillPropagate()
    {
        var (context, _) = NewContext("/connect/token");

        var act = () => Sut(_ => throw new InvalidOperationException("bug")).InvokeAsync(context);

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task OtherPathsAreNotTouched()
    {
        var (context, _) = NewContext("/connect/authorize");

        var act = () => Sut(_ => throw Unauthorized()).InvokeAsync(context);

        await act.Should().ThrowAsync<MongoCommandException>();
    }

    [Fact]
    public async Task ASuccessfulRequest_PassesThrough()
    {
        var (context, _) = NewContext("/connect/token");
        var called = false;

        await Sut(_ =>
        {
            called = true;
            return Task.CompletedTask;
        }).InvokeAsync(context);

        called.Should().BeTrue();
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK);
    }
}
