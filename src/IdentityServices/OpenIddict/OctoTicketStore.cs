using System.Security.Claims;
using System.Security.Cryptography;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.OpenIddict;

/// <summary>
///     Server-side session store for the ASP.NET Identity application cookie (AB#4994), replacing
///     Duende's <c>AddServerSideSessions</c>/<c>ServerSideSessionStore</c> pair: the browser cookie
///     carries only the short session key, the data-protected
///     <see cref="AuthenticationTicket" /> lives in the per-tenant
///     <see cref="RtServerSideSession" /> CK entity (same type, new ticket serialization — old
///     Duende tickets are unreadable, which is fine: all sessions end at the cutover, see
///     docs/CONCEPT-OPENIDDICT-MIGRATION.md §2).
/// </summary>
/// <remarks>
///     <para>
///         Registered as a singleton (the cookie handler holds one instance); the per-tenant
///         repository is resolved per call through the request-scoped
///         <see cref="IMultiTenancyResolverService" /> obtained from the current
///         <see cref="HttpContext" /> — mirroring the lazy tenant-resolution rule of all other
///         stores. Expired records are treated as missing on read and physically removed by
///         <c>TokenCleanupHostService</c> (system + all child tenants).
///     </para>
///     <para>
///         A <c>sid</c> claim is stamped onto the ticket principal when a session is created —
///         it is the session identifier tokens carry (Duende parity) and what front-channel
///         logout uses to address the session.
///     </para>
/// </remarks>
public class OctoTicketStore(
    IHttpContextAccessor httpContextAccessor,
    IDataProtectionProvider dataProtectionProvider,
    ILogger<OctoTicketStore> logger) : ITicketStore
{
    private const string DataProtectionPurpose = "OctoTicketStore";

    private readonly TicketSerializer _serializer = TicketSerializer.Default;
    private readonly IDataProtector _protector = dataProtectionProvider.CreateProtector(DataProtectionPurpose);

    public async Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var sessionKey = GenerateSessionKey();
        var sessionId = GenerateSessionId();

        // Stamp the session id onto the principal BEFORE serializing: tokens issued from this
        // session copy the sid claim (Duende parity), and logout revokes by it.
        var identity = ticket.Principal.Identities.First();
        if (!identity.HasClaim(c => c.Type == "sid"))
        {
            identity.AddClaim(new Claim("sid", sessionId));
        }

        var session = new RtServerSideSession
        {
            RtId = OctoObjectId.GenerateNewId(),
            SessionKey = sessionKey,
            Scheme = ticket.AuthenticationScheme,
            SubjectId = ticket.Principal.FindFirstValue("sub")
                        ?? ticket.Principal.FindFirstValue(ClaimTypes.NameIdentifier)
                        ?? string.Empty,
            SessionId = sessionId,
            DisplayName = ticket.Principal.Identity?.Name,
            CreationDateTime = DateTime.UtcNow,
            RenewalDateTime = DateTime.UtcNow,
            ExpirationDateTime = ticket.Properties.ExpiresUtc?.UtcDateTime,
            Ticket = ProtectTicket(ticket)
        };

        await MongoWriteRetry.ExecuteWithRetryAsync(async () =>
        {
            var repository = ResolveTenantRepository();
            using var session2 = await repository.GetSessionAsync();
            session2.StartTransaction();
            await repository.InsertOneRtEntityAsync(session2, session);
            await session2.CommitTransactionAsync();
        });

        return sessionKey;
    }

    public async Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        await MongoWriteRetry.ExecuteWithRetryAsync(async () =>
        {
            var repository = ResolveTenantRepository();
            using var session = await repository.GetSessionAsync();
            session.StartTransaction();

            var existing = await GetByKeyAsync(repository, session, key);
            if (existing == null)
            {
                // The record was concurrently swept — recreate it so the cookie stays valid
                // (parity with the previous ServerSideSessionStore.UpdateSessionAsync behavior).
                existing = new RtServerSideSession
                {
                    RtId = OctoObjectId.GenerateNewId(),
                    SessionKey = key,
                    Scheme = ticket.AuthenticationScheme,
                    CreationDateTime = DateTime.UtcNow,
                    SessionId = ticket.Principal.FindFirstValue("sid") ?? GenerateSessionId()
                };
                UpdateRecord(existing, ticket);
                await repository.InsertOneRtEntityAsync(session, existing);
            }
            else
            {
                UpdateRecord(existing, ticket);
                await repository.ReplaceOneRtEntityByIdAsync(session, existing.RtId, existing);
            }

            await session.CommitTransactionAsync();
        });
    }

    public async Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        var repository = ResolveTenantRepository();
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        var record = await GetByKeyAsync(repository, session, key);
        await session.CommitTransactionAsync();

        // Expired-but-not-yet-swept records are missing for authentication purposes.
        if (record?.Ticket == null ||
            (record.ExpirationDateTime.HasValue && record.ExpirationDateTime.Value <= DateTime.UtcNow))
        {
            return null;
        }

        try
        {
            return _serializer.Deserialize(_protector.Unprotect(Convert.FromBase64String(record.Ticket)));
        }
        catch (Exception ex)
        {
            // Unreadable ticket (key-ring rotation edge case or a legacy Duende-format record):
            // treat as signed out instead of failing every request of this browser.
            logger.LogWarning(ex, "Failed to deserialize server-side session ticket for key prefix '{KeyPrefix}…'",
                key.Length > 8 ? key[..8] : key);
            return null;
        }
    }

    public async Task RemoveAsync(string key)
    {
        var repository = ResolveTenantRepository();
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        var filter = FieldFilterCriteria.Create(LogicalOperators.And)
            .FieldEquals(nameof(RtServerSideSession.SessionKey), key);
        await repository.DeleteManyRtEntitiesAsync<RtServerSideSession>(session, filter, DeleteOptions.Erase);
        await session.CommitTransactionAsync();
    }

    private void UpdateRecord(RtServerSideSession record, AuthenticationTicket ticket)
    {
        record.SubjectId = ticket.Principal.FindFirstValue("sub")
                           ?? ticket.Principal.FindFirstValue(ClaimTypes.NameIdentifier)
                           ?? record.SubjectId;
        record.DisplayName = ticket.Principal.Identity?.Name ?? record.DisplayName;
        record.RenewalDateTime = DateTime.UtcNow;
        record.ExpirationDateTime = ticket.Properties.ExpiresUtc?.UtcDateTime;
        record.Ticket = ProtectTicket(ticket);
    }

    private string ProtectTicket(AuthenticationTicket ticket)
        => Convert.ToBase64String(_protector.Protect(_serializer.Serialize(ticket)));

    private static async Task<RtServerSideSession?> GetByKeyAsync(
        ITenantRepository repository, IOctoSession session, string key)
    {
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtServerSideSession.SessionKey), FieldFilterOperator.Equals, key);
        var result = await repository.GetRtEntitiesByTypeAsync<RtServerSideSession>(session, queryOptions);
        return result.Items.FirstOrDefault();
    }

    /// <summary>
    ///     Resolves the per-tenant repository through the request-scoped resolver — the cookie
    ///     middleware always runs inside a request, after <c>OidcTenantResolutionMiddleware</c> or
    ///     the tenant route segment wired the tenant into <c>HttpContext.Items</c>.
    /// </summary>
    private ITenantRepository ResolveTenantRepository()
    {
        var httpContext = httpContextAccessor.HttpContext
                          ?? throw new InvalidOperationException(
                              "OctoTicketStore requires an active HTTP request to resolve the tenant.");
        return httpContext.RequestServices
            .GetRequiredService<IMultiTenancyResolverService>()
            .GetTenantRepository();
    }

    private static string GenerateSessionKey()
        => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));

    private static string GenerateSessionId()
        => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
}
