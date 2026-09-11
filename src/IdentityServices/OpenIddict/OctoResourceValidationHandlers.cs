using System.Collections.Immutable;
using IdentityServerPersistence.SystemStores.OpenIddict;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Meshmakers.Octo.Backend.IdentityServices.OpenIddict;

/// <summary>
///     Store-backed validation of the RFC 8707 <c>resource</c> parameter (AB#5193), replacing
///     OpenIddict's three built-in <c>ValidateResources</c> handlers.
/// </summary>
/// <remarks>
///     <para>
///         The built-ins compare the requested indicators against
///         <c>OpenIddictServerOptions.Resources</c> — a static allow-list filled by
///         <c>RegisterResources(...)</c> at composition time. A multi-tenant server cannot use it:
///         API resources live per tenant in MongoDB and are created at runtime by the TenantApi and
///         by blueprint seeding. Left unfilled (as it is), the list rejects <b>every</b> resource
///         indicator with <c>invalid_target</c>, which is what broke interactive MCP logins after
///         the Duende → OpenIddict migration — Duende validated against the API resource store.
///     </para>
///     <para>
///         These handlers keep the built-in contract byte for byte (same descriptor order, same
///         <c>RequireResourceValidationEnabled</c> filter, same error code, description and
///         documentation URI as OpenIddict's ID2190) and only add the fallback the OpenIddict 8.x
///         line introduces upstream: whatever the static list does not cover is resolved through
///         <see cref="IOpenIddictResourceStore{TResource}" />, i.e. against the requesting
///         tenant's own API resources. On the 8.x upgrade this file is deleted — see that
///         interface for the migration note.
///     </para>
///     <para>
///         The three variants live in one file on purpose: authorize, pushed authorize (PAR) and
///         token must accept exactly the same set of indicators, or a client that pushes its
///         request gets a different answer than one that does not.
///     </para>
/// </remarks>
public static class OctoResourceValidationHandlers
{
    // OpenIddict's own ID2190 text and error URI (its SR resources are internal) — the rejection
    // stays indistinguishable on the wire from the built-in one.
    private const string InvalidResourceDescription = "One of the specified 'resource' parameters is invalid.";
    private const string InvalidResourceUri = "https://documentation.openiddict.com/errors/ID2190";

    /// <summary>Authorization endpoint — replaces <c>Authentication.ValidateResources</c>.</summary>
    public class Authorization(IOpenIddictResourceStore<RtApiResource> resourceStore)
        : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
    {
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                .AddFilter<OpenIddictServerHandlerFilters.RequireResourceValidationEnabled>()
                .UseScopedHandler<Authorization>()
                .SetOrder(OpenIddictServerHandlers.Authentication.ValidateResources.Descriptor.Order)
                .SetType(OpenIddictServerHandlerType.Custom)
                .Build();

        public async ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            var unknown = await FindUnknownResourcesAsync(resourceStore, context.Request, context.Options,
                context.CancellationToken);
            if (unknown.Count == 0)
            {
                return;
            }

            context.Logger.LogInformation(
                "The authorization request was rejected because invalid resources were specified: {Resources}.",
                unknown);

            context.Reject(Errors.InvalidTarget, InvalidResourceDescription, InvalidResourceUri);
        }
    }

    /// <summary>Pushed authorization endpoint — replaces <c>Authentication.ValidatePushedResources</c>.</summary>
    public class PushedAuthorization(IOpenIddictResourceStore<RtApiResource> resourceStore)
        : IOpenIddictServerHandler<ValidatePushedAuthorizationRequestContext>
    {
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidatePushedAuthorizationRequestContext>()
                .AddFilter<OpenIddictServerHandlerFilters.RequireResourceValidationEnabled>()
                .UseScopedHandler<PushedAuthorization>()
                .SetOrder(OpenIddictServerHandlers.Authentication.ValidatePushedResources.Descriptor.Order)
                .SetType(OpenIddictServerHandlerType.Custom)
                .Build();

        public async ValueTask HandleAsync(ValidatePushedAuthorizationRequestContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            var unknown = await FindUnknownResourcesAsync(resourceStore, context.Request, context.Options,
                context.CancellationToken);
            if (unknown.Count == 0)
            {
                return;
            }

            context.Logger.LogInformation(
                "The pushed authorization request was rejected because invalid resources were specified: {Resources}.",
                unknown);

            context.Reject(Errors.InvalidTarget, InvalidResourceDescription, InvalidResourceUri);
        }
    }

    /// <summary>Token endpoint — replaces <c>Exchange.ValidateResources</c>.</summary>
    public class Token(IOpenIddictResourceStore<RtApiResource> resourceStore)
        : IOpenIddictServerHandler<ValidateTokenRequestContext>
    {
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
                .AddFilter<OpenIddictServerHandlerFilters.RequireResourceValidationEnabled>()
                .UseScopedHandler<Token>()
                .SetOrder(OpenIddictServerHandlers.Exchange.ValidateResources.Descriptor.Order)
                .SetType(OpenIddictServerHandlerType.Custom)
                .Build();

        public async ValueTask HandleAsync(ValidateTokenRequestContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            var unknown = await FindUnknownResourcesAsync(resourceStore, context.Request, context.Options,
                context.CancellationToken);
            if (unknown.Count == 0)
            {
                return;
            }

            context.Logger.LogInformation(
                "The token request was rejected because invalid resources were specified: {Resources}.",
                unknown);

            context.Reject(Errors.InvalidTarget, InvalidResourceDescription, InvalidResourceUri);
        }
    }

    /// <summary>
    ///     The requested resource indicators the request may not use — unknown to this tenant,
    ///     disabled, or unrelated to the requested scopes. Empty means the request passes.
    /// </summary>
    private static async ValueTask<IReadOnlyCollection<string>> FindUnknownResourcesAsync(
        IOpenIddictResourceStore<RtApiResource> resourceStore,
        OpenIddictRequest request,
        OpenIddictServerOptions options,
        CancellationToken cancellationToken)
    {
        // Statically registered resources short-circuit the database, exactly as the built-in
        // handlers do. The list is empty today; keeping the fast path means the built-in behavior
        // stays a strict subset of this one.
        var resources = request.GetResources().ToHashSet(StringComparer.Ordinal);
        resources.ExceptWith(options.Resources.Select(static resource => resource.AbsoluteUri));

        if (resources.Count == 0)
        {
            return Array.Empty<string>();
        }

        var requestedScopes = request.GetScopes();

        // The store answers with the identifiers as STORED, which may differ from the requested
        // spelling by a trailing slash — hence the slash-insensitive set.
        var usable = new HashSet<string>(ResourceIdentifiers.Comparer);
        await foreach (var resource in resourceStore.FindByNamesAsync([.. resources], cancellationToken))
        {
            var name = await resourceStore.GetNameAsync(resource, cancellationToken);
            if (!string.IsNullOrEmpty(name) && CoversRequestedScopes(resource, requestedScopes))
            {
                usable.Add(name);
            }
        }

        resources.RemoveWhere(usable.Contains);
        return resources;
    }

    /// <summary>
    ///     Whether the indicator relates to what is being asked for — the pre-migration rule: an
    ///     indicator narrows the request to an API resource, so that resource has to carry at
    ///     least one of the requested scopes.
    /// </summary>
    /// <remarks>
    ///     A request without a <c>scope</c> parameter — a refresh renewal, which is exactly the
    ///     MCP failure this replaces — cannot be judged that way: the granted scopes live in the
    ///     refresh token and are not resolved yet at request validation. Registration alone
    ///     decides there, and the scopes carried over from the original grant still determine the
    ///     audiences of the renewed token.
    /// </remarks>
    private static bool CoversRequestedScopes(RtApiResource resource, ImmutableArray<string> requestedScopes)
        => requestedScopes.Length == 0 ||
           requestedScopes.Any(scope => resource.Scopes.Contains(scope, StringComparer.Ordinal));
}
