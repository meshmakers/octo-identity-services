using System.Collections.Immutable;
using System.Globalization;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServerPersistence.SystemStores.OpenIddict;

/// <summary>
///     OpenIddict application store projecting the existing per-tenant <see cref="RtClient" />
///     entities (AB#4991). Purely a read-time mapping layer: the stored client data is unchanged,
///     the Duende-shaped configuration is transformed into OpenIddict's permissions model by
///     <see cref="ClientPermissionsMapper" />.
/// </summary>
/// <remarks>
///     <para>
///         The application identifier exposed to OpenIddict (<see cref="GetIdAsync" />) is the
///         OAuth <c>client_id</c>, which is unique per tenant — authorization and token records
///         therefore reference clients by <c>client_id</c>, which also keeps mirrored clients
///         (identical <c>client_id</c>, different <c>RtId</c> per tenant DB) correlated correctly.
///     </para>
///     <para>
///         Tenant resolution matches every other store in this folder: the tenant repository is
///         resolved lazily per call from the HTTP context wired by
///         <c>OidcTenantResolutionMiddleware</c> — never in the constructor.
///     </para>
///     <para>
///         Write operations are intentionally unsupported: all client CRUD (TenantApi
///         controllers, DCR, mirror provisioning) goes through <see cref="IOctoClientStore" />,
///         which owns the mirror upkeep hooks.
///     </para>
/// </remarks>
public class OpenIddictApplicationStore(
    IOctoClientStore clientStore) : IOpenIddictApplicationStore<RtClient>
{
    private const string WritesUnsupportedMessage =
        "Client write operations go through IOctoClientStore (mirror upkeep hooks), not OpenIddict.";

    public ValueTask<long> CountAsync(CancellationToken cancellationToken)
        => throw new NotSupportedException("Counting applications through OpenIddict is not supported.");

    public ValueTask<long> CountAsync<TResult>(
        Func<IQueryable<RtClient>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        => throw new NotSupportedException("LINQ queries against the client store are not supported.");

    public ValueTask CreateAsync(RtClient application, CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public ValueTask DeleteAsync(RtClient application, CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public async ValueTask<RtClient?> FindByClientIdAsync(string identifier, CancellationToken cancellationToken)
    {
        var client = await clientStore.FindRtClientByIdAsync(identifier);
        if (client is not { Enabled: true })
        {
            return null;
        }

        // RFC 7591 DCR clients carry a TTL — an expired dynamic client no longer exists
        // for protocol purposes (same gate ClientStore.FindClientByIdAsync applied for Duende).
        if (client.DynamicRegistration &&
            client.DynamicRegistrationExpiresAt is { } expiresAt &&
            expiresAt <= DateTime.UtcNow)
        {
            return null;
        }

        return client;
    }

    // The application identifier IS the client_id (see class remarks).
    public ValueTask<RtClient?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
        => FindByClientIdAsync(identifier, cancellationToken);

    public async IAsyncEnumerable<RtClient> FindByPostLogoutRedirectUriAsync(
        string uri, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var client in await clientStore.GetClients())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (client.Enabled &&
                client.PostLogoutRedirectUris?.Any(e => string.Equals(e.Uri, uri, StringComparison.Ordinal)) == true)
            {
                yield return client;
            }
        }
    }

    public async IAsyncEnumerable<RtClient> FindByRedirectUriAsync(
        string uri, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var client in await clientStore.GetClients())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (client.Enabled &&
                client.RedirectUris?.Any(e => string.Equals(e.Uri, uri, StringComparison.Ordinal)) == true)
            {
                yield return client;
            }
        }
    }

    public ValueTask<string?> GetApplicationTypeAsync(RtClient application, CancellationToken cancellationToken)
        => new((string?)null);

    public ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<RtClient>, TState, IQueryable<TResult>> query, TState state,
        CancellationToken cancellationToken)
        => throw new NotSupportedException("LINQ queries against the client store are not supported.");

    public ValueTask<string?> GetClientIdAsync(RtClient application, CancellationToken cancellationToken)
        => new(application.ClientId);

    public ValueTask<string?> GetClientSecretAsync(RtClient application, CancellationToken cancellationToken)
    {
        // Returns the stored Duende-format hash (Base64 SHA-256/512 of the secret).
        // OctoApplicationManager owns the comparison so existing secrets keep working.
        var secret = application.ClientSecrets?
            .Where(s => s.ExpirationDateTime == null || s.ExpirationDateTime > DateTime.UtcNow)
            .Select(s => s.Value)
            .FirstOrDefault(v => !string.IsNullOrEmpty(v));
        return new ValueTask<string?>(secret);
    }

    public ValueTask<string?> GetClientTypeAsync(RtClient application, CancellationToken cancellationToken)
        => new(application.RequireClientSecret ? ClientTypes.Confidential : ClientTypes.Public);

    public ValueTask<string?> GetConsentTypeAsync(RtClient application, CancellationToken cancellationToken)
        => new(application.RequireConsent == true ? ConsentTypes.Explicit : ConsentTypes.Implicit);

    public ValueTask<string?> GetDisplayNameAsync(RtClient application, CancellationToken cancellationToken)
        => new(application.ClientName);

    public ValueTask<ImmutableDictionary<CultureInfo, string>> GetDisplayNamesAsync(
        RtClient application, CancellationToken cancellationToken)
        => new(ImmutableDictionary<CultureInfo, string>.Empty);

    public ValueTask<string?> GetIdAsync(RtClient application, CancellationToken cancellationToken)
        => new(application.ClientId);

    public ValueTask<JsonWebKeySet?> GetJsonWebKeySetAsync(RtClient application, CancellationToken cancellationToken)
        => new((JsonWebKeySet?)null);

    public ValueTask<ImmutableArray<string>> GetPermissionsAsync(
        RtClient application, CancellationToken cancellationToken)
        => new(ClientPermissionsMapper.MapPermissions(application));

    public ValueTask<ImmutableArray<string>> GetPostLogoutRedirectUrisAsync(
        RtClient application, CancellationToken cancellationToken)
        => new(MapUris(application.PostLogoutRedirectUris));

    public ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(
        RtClient application, CancellationToken cancellationToken)
        => new(ImmutableDictionary<string, JsonElement>.Empty);

    public ValueTask<ImmutableArray<string>> GetRedirectUrisAsync(
        RtClient application, CancellationToken cancellationToken)
        => new(MapUris(application.RedirectUris));

    public ValueTask<ImmutableArray<string>> GetRequirementsAsync(
        RtClient application, CancellationToken cancellationToken)
        => new(ClientPermissionsMapper.MapRequirements(application));

    public ValueTask<ImmutableDictionary<string, string>> GetSettingsAsync(
        RtClient application, CancellationToken cancellationToken)
    {
        // Per-client token lifetimes, mapped from the Duende second-based configuration.
        var settings = ImmutableDictionary.CreateBuilder<string, string>(StringComparer.Ordinal);
        AddLifetime(settings, Settings.TokenLifetimes.AccessToken, application.AccessTokenLifetime);
        AddLifetime(settings, Settings.TokenLifetimes.IdentityToken, application.IdentityTokenLifetime);
        AddLifetime(settings, Settings.TokenLifetimes.AuthorizationCode, application.AuthorizationCodeLifetime);
        AddLifetime(settings, Settings.TokenLifetimes.DeviceCode, application.DeviceCodeLifetime);
        AddLifetime(settings, Settings.TokenLifetimes.UserCode, application.DeviceCodeLifetime);
        AddLifetime(settings, Settings.TokenLifetimes.RefreshToken, application.AbsoluteRefreshTokenLifetime);
        return new ValueTask<ImmutableDictionary<string, string>>(settings.ToImmutable());
    }

    public ValueTask<RtClient> InstantiateAsync(CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public async IAsyncEnumerable<RtClient> ListAsync(
        int? count, int? offset, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        IEnumerable<RtClient> clients = await clientStore.GetClients();
        if (offset is { } o)
        {
            clients = clients.Skip(o);
        }

        if (count is { } c)
        {
            clients = clients.Take(c);
        }

        foreach (var client in clients)
        {
            yield return client;
        }
    }

    public IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<RtClient>, TState, IQueryable<TResult>> query, TState state,
        CancellationToken cancellationToken)
        => throw new NotSupportedException("LINQ queries against the client store are not supported.");

    public ValueTask SetApplicationTypeAsync(RtClient application, string? type, CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public ValueTask SetClientIdAsync(RtClient application, string? identifier, CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public ValueTask SetClientSecretAsync(RtClient application, string? secret, CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public ValueTask SetClientTypeAsync(RtClient application, string? type, CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public ValueTask SetConsentTypeAsync(RtClient application, string? type, CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public ValueTask SetDisplayNameAsync(RtClient application, string? name, CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public ValueTask SetDisplayNamesAsync(RtClient application,
        ImmutableDictionary<CultureInfo, string> names, CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public ValueTask SetJsonWebKeySetAsync(RtClient application, JsonWebKeySet? set,
        CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public ValueTask SetPermissionsAsync(RtClient application, ImmutableArray<string> permissions,
        CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public ValueTask SetPostLogoutRedirectUrisAsync(RtClient application, ImmutableArray<string> uris,
        CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public ValueTask SetPropertiesAsync(RtClient application,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public ValueTask SetRedirectUrisAsync(RtClient application, ImmutableArray<string> uris,
        CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public ValueTask SetRequirementsAsync(RtClient application, ImmutableArray<string> requirements,
        CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public ValueTask SetSettingsAsync(RtClient application, ImmutableDictionary<string, string> settings,
        CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public ValueTask UpdateAsync(RtClient application, CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    private static ImmutableArray<string> MapUris(IEnumerable<RtClientUriEntryRecord>? entries)
    {
        if (entries == null)
        {
            return ImmutableArray<string>.Empty;
        }

        return entries
            .Select(e => e.Uri)
            .Where(u => !string.IsNullOrWhiteSpace(u))
            .Select(u => u!)
            .Distinct(StringComparer.Ordinal)
            .ToImmutableArray();
    }

    private static void AddLifetime(
        ImmutableDictionary<string, string>.Builder settings, string key, int? seconds)
    {
        if (seconds is > 0)
        {
            settings[key] = TimeSpan.FromSeconds(seconds.Value).ToString("c", CultureInfo.InvariantCulture);
        }
    }
}
