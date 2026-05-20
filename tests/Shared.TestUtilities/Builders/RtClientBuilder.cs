using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Shared.TestUtilities.Builders;

public class RtClientBuilder
{
    private readonly RtClient _client = new()
    {
        RtId = OctoObjectId.GenerateNewId(),
        ClientId = "default-client",
        ClientName = "Default Client",
        Enabled = true,
        RequirePkce = true,
        RequireClientSecret = false,
        AllowedGrantTypes = new AttributeStringValueList { "authorization_code" },
        AllowedScopes = new AttributeStringValueList { "openid", "profile", "email" },
        RedirectUris = new AttributeStringValueList(),
        PostLogoutRedirectUris = new AttributeStringValueList(),
        AllowedCorsOrigins = new AttributeStringValueList(),
        ProtocolType = "oidc"
    };

    public RtClientBuilder WithRtId(OctoObjectId rtId)
    {
        _client.RtId = rtId;
        return this;
    }

    public RtClientBuilder WithClientId(string clientId)
    {
        _client.ClientId = clientId;
        return this;
    }

    public RtClientBuilder WithClientName(string name)
    {
        _client.ClientName = name;
        return this;
    }

    public RtClientBuilder WithDescription(string description)
    {
        _client.Description = description;
        return this;
    }

    public RtClientBuilder WithGrantTypes(params string[] grantTypes)
    {
        _client.AllowedGrantTypes = new AttributeStringValueList(grantTypes.ToList());
        return this;
    }

    public RtClientBuilder WithScopes(params string[] scopes)
    {
        _client.AllowedScopes = new AttributeStringValueList(scopes.ToList());
        return this;
    }

    public RtClientBuilder WithRedirectUris(params string[] uris)
    {
        _client.RedirectUris = new AttributeStringValueList(uris.ToList());
        return this;
    }

    public RtClientBuilder WithPostLogoutRedirectUris(params string[] uris)
    {
        _client.PostLogoutRedirectUris = new AttributeStringValueList(uris.ToList());
        return this;
    }

    public RtClientBuilder WithCorsOrigins(params string[] origins)
    {
        _client.AllowedCorsOrigins = new AttributeStringValueList(origins.ToList());
        return this;
    }

    public RtClientBuilder WithSecret(string type, string value, string? description = null)
    {
        _client.ClientSecrets ??= new AttributeRecordValueList<RtSecretRecord>();
        _client.ClientSecrets.Add(new RtSecretRecord
        {
            Type = type,
            Value = value,
            Description = description
        });
        return this;
    }

    public RtClientBuilder RequireClientSecret(bool required = true)
    {
        _client.RequireClientSecret = required;
        return this;
    }

    public RtClientBuilder RequirePkce(bool required = true)
    {
        _client.RequirePkce = required;
        return this;
    }

    public RtClientBuilder WithAccessTokenLifetime(int seconds)
    {
        _client.AccessTokenLifetime = seconds;
        return this;
    }

    public RtClientBuilder Disabled()
    {
        _client.Enabled = false;
        return this;
    }

    public RtClientBuilder Enabled()
    {
        _client.Enabled = true;
        return this;
    }

    public RtClientBuilder WithFrontChannelLogoutUri(string uri)
    {
        _client.FrontChannelLogoutUri = uri;
        return this;
    }

    public RtClientBuilder WithBackChannelLogoutUri(string uri)
    {
        _client.BackChannelLogoutUri = uri;
        return this;
    }

    public RtClientBuilder WithFrontChannelLogoutSessionRequired(bool required = true)
    {
        _client.FrontChannelLogoutSessionRequired = required;
        return this;
    }

    public RtClientBuilder WithBackChannelLogoutSessionRequired(bool required = true)
    {
        _client.BackChannelLogoutSessionRequired = required;
        return this;
    }

    public RtClientBuilder WithClientUri(string uri)
    {
        _client.ClientUri = uri;
        return this;
    }

    public RtClientBuilder WithLogoUri(string uri)
    {
        _client.LogoUri = uri;
        return this;
    }

    public RtClientBuilder WithAllowRememberConsent(bool allow = true)
    {
        _client.AllowRememberConsent = allow;
        return this;
    }

    public RtClientBuilder WithAllowOfflineAccess(bool allow = true)
    {
        _client.AllowOfflineAccess = allow;
        return this;
    }

    public RtClientBuilder WithRefreshTokenLifetime(int seconds)
    {
        _client.AbsoluteRefreshTokenLifetime = seconds;
        return this;
    }

    public RtClientBuilder WithIdentityTokenLifetime(int seconds)
    {
        _client.IdentityTokenLifetime = seconds;
        return this;
    }

    public RtClient Build() => _client;
}
