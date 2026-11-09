using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     AB#8571: resolves the client named as a group member — by its rtId or by its OAuth client id — for the REST endpoints
///     <c>PUT/DELETE {tenant}/v1/groups/{group}/members/clients/{client}</c> and the methods <c>Group.AddMember</c> /
///     <c>Group.RemoveMember</c>, so both accept the same values.
/// </summary>
/// <remarks>
///     The rtId wins: a value that is a valid rtId of an existing client is that client. Otherwise the value is looked up as
///     a client id — this also covers a client id that happens to look like an rtId (24 hex digits). Before AB#8571 the REST
///     path passed a client id straight into <c>new OctoObjectId(…)</c> and answered 500; the methods resolved only
///     non-hex values.
/// </remarks>
internal static class GroupClientMemberResolver
{
    /// <summary>The client, or <c>null</c> when no client has this rtId or client id.</summary>
    public static async Task<RtClient?> ResolveAsync(IOctoClientStore clientStore, ITenantRepository repository,
        string memberId)
    {
        if (string.IsNullOrWhiteSpace(memberId))
        {
            return null;
        }

        memberId = memberId.Trim();
        if (OctoObjectId.TryParse(memberId, out var rtId))
        {
            using var session = await repository.GetSessionAsync().ConfigureAwait(false);
            session.StartTransaction();
            var byRtId = await repository.GetRtEntityByRtIdAsync<RtClient>(session, rtId).ConfigureAwait(false);
            await session.CommitTransactionAsync().ConfigureAwait(false);
            if (byRtId != null)
            {
                return byRtId;
            }
        }

        return await clientStore.FindRtClientByIdAsync(memberId).ConfigureAwait(false);
    }
}
