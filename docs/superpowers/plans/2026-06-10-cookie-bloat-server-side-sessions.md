# Cookie-Bloat Fix: Server-Side Sessions + MongoDB DataProtection Key Ring

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse the ~3 KB per-tenant `.AspNetCore.Identity.Application.<tenant>` cookies to small session keys via Duende server-side sessions stored as CK entities in MongoDB, and make DataProtection key-ring persistence always-on (MongoDB-backed, with zero-logout seed import from the legacy file path).

**Architecture:** Two new CK types in `System.Identity` 2.7.0 (`ServerSideSession`, `DataProtectionKey`). `ServerSideSessionStore : IServerSideSessionStore` clones the `PersistentGrantStore` pattern (per-request tenant via `IMultiTenancyResolverService`; cleanup iterates tenants via `ISystemContext` like `TokenCleanupHostService`). `DataProtectionKeyStore : IXmlRepository` persists the key ring in the **system tenant** (service-global data) and seeds once from `Identity:DataProtectionKeysPath` XML files. Helm chart + deployment values drop the `dataProtection` toggle/PVC/Recreate. Ship identity image FIRST (old chart still mounts the PVC → seed import runs), chart deletion second.

**Tech Stack:** .NET 10, Duende IdentityServer 7.4.7 (`AddServerSideSessions<T>()`), Octo Runtime Engine MongoDB, CK source generation (`Meshmakers.Octo.ConstructionKit.SourceGeneration` — Rt* classes generated at build, no codegen script), AutoMapper 16, xunit.v3 + NSubstitute + FluentAssertions + Testcontainers.MongoDb.

**Branch:** `dev/server-side-sessions` (already created). **Build:** `dotnet build Octo.Identity.sln -c DebugL`. **Tests:** `dotnet test Octo.Identity.sln -c DebugL` (use DebugL — local NuGet feed; repo CLAUDE.md's `-c Release` requires the private feed). **Never push — Reimar reviews first.**

---

## File Map

| Action | Path | Responsibility |
|---|---|---|
| Modify | `src/Persistence.IdentityCkModel/ConstructionKit/ckModel.yaml` | modelId 2.6.0 → 2.7.0 |
| Create | `src/Persistence.IdentityCkModel/ConstructionKit/types/ck-serverSideSession.yaml` | ServerSideSession CK type + indexes |
| Create | `src/Persistence.IdentityCkModel/ConstructionKit/types/ck-dataProtectionKey.yaml` | DataProtectionKey CK type + unique index |
| Modify | `src/Persistence.IdentityCkModel/ConstructionKit/attributes/identity-attributes.yaml` | 7 new attributes (append at end) |
| Create | `src/IdentityServerPersistence/Services/Migrations/ServerSideSessionMigration.cs` | Migration 16→17: `UpdateIndexesAsync` |
| Create | `src/IdentityServerPersistence/SystemStores/ServerSideSessionStore.cs` | `IServerSideSessionStore` impl |
| Create | `src/IdentityServerPersistence/SystemStores/DataProtectionKeyStore.cs` | `IXmlRepository` impl + seed import |
| Modify | `src/IdentityServerPersistence/Configuration/DependencyInjection/RuntimeEngineBuilderExtensions.cs` | AutoMapper maps for ServerSideSession |
| Modify | `src/IdentityServices/Program.cs` | always-on DP wiring; `.AddServerSideSessions<ServerSideSessionStore>()`; `ExpireTimeSpan` |
| Modify | `src/IdentityServerPersistence/Configuration/Options/OctoIdentityServicesOptions.cs` | doc-comment update on `DataProtectionKeysPath` (seed-only) |
| Create | `tests/IdentityServerPersistence.UnitTests/Stores/ServerSideSessionStoreTests.cs` | store unit tests (NSubstitute) |
| Create | `tests/IdentityServices.IntegrationTests/Persistence/ServerSideSessionStoreIntegrationTests.cs` | real-Mongo session round-trips |
| Create | `tests/IdentityServices.IntegrationTests/Persistence/DataProtectionKeyStoreIntegrationTests.cs` | key ring persistence + seed import |
| Modify | `CLAUDE.md`, `docs/persistence.md`, `docs/authentication.md` | documentation (mandatory per repo rules) |
| Modify (octo-helm-core) | `src/octo-mesh/templates/{pvc.yaml,_env.tpl,deployment.yaml}`, `values.yaml`, `README.md` | delete dataProtection feature surface |
| Modify (deployment/octo-mesh-deployment) | `base/values-octo-mesh.yaml`, `clusters/prod-1/...`, `clusters/test-2/...` | strip dataProtection blocks |

Key facts an engineer must know (verified from source):
- CK types live in **separate YAML files**; the 4-line `ckModel.yaml` only holds `modelId` + dependencies. The Roslyn source generator emits `RtServerSideSession`/`RtDataProtectionKey` (namespace `Persistence.IdentityCkModel.Generated.System.Identity.v2`) automatically on build — **no codegen command exists or is needed**.
- Transaction pattern everywhere: `using var session = await repo.GetSessionAsync(); session.StartTransaction(); ...; await session.CommitTransactionAsync();`
- `IMultiTenancyResolverService.GetTenantRepository()` resolves the per-request tenant (set by `OidcTenantResolutionMiddleware`). **It cannot be used off the HTTP request path** — background work (DP key ring, expired-session sweep) must use `ISystemContext` (`GetSystemTenantRepositoryAsAdmin()`, `GetChildTenantsAsync`, `TryFindTenantRepositoryAsync`) like `TokenCleanupHostService` does.
- `IdentityServerPersistence.csproj` already has `<FrameworkReference Include="Microsoft.AspNetCore.App" />` → `IXmlRepository` available, no new package.
- Duende 7.4.7 contract (verified from package XML docs): `ServerSideSession { string Key, Scheme, SubjectId, SessionId, DisplayName; DateTime Created, Renewed; DateTime? Expires; string Ticket }`; `IServerSideSessionStore` has 8 methods; registration via `identityServerBuilder.AddServerSideSessions<TStore>()` (namespace `Microsoft.Extensions.DependencyInjection`, class `SessionManagementServiceCollectionExtensions`).
- Migration chain: current highest is 15→16 (`ClientProvisionedByParentMigration`). New migration is **16→17** with key `IdentityServiceConstants.IdentityMigrationVersionKey`; auto-discovered via `AddMigrations(typeof(IdentityServiceConstants).Assembly)`.

---

### Task 1: CK model 2.7.0 — types, attributes, migration

**Files:**
- Modify: `src/Persistence.IdentityCkModel/ConstructionKit/ckModel.yaml`
- Create: `src/Persistence.IdentityCkModel/ConstructionKit/types/ck-serverSideSession.yaml`
- Create: `src/Persistence.IdentityCkModel/ConstructionKit/types/ck-dataProtectionKey.yaml`
- Modify: `src/Persistence.IdentityCkModel/ConstructionKit/attributes/identity-attributes.yaml`
- Create: `src/IdentityServerPersistence/Services/Migrations/ServerSideSessionMigration.cs`

- [ ] **Step 1.1: Bump modelId** in `ckModel.yaml` — change line 2 `modelId: System.Identity-2.6.0` → `modelId: System.Identity-2.7.0` (rest of the 4-line file unchanged).

- [ ] **Step 1.2: Append 7 new attributes** at the end of `attributes/identity-attributes.yaml`:

```yaml

  - id: SessionKey
    valueType: String
    description: Unique key of a Duende server-side session (the only value stored in the browser cookie).

  - id: Scheme
    valueType: String
    description: The ASP.NET authentication scheme that produced the session ticket.

  - id: DisplayName
    valueType: String
    description: Optional display name of the user owning the session.

  - id: RenewalDateTime
    valueType: DateTime
    description: UTC timestamp of the last sliding-expiration renewal of the session.

  - id: Ticket
    valueType: String
    description: The serialized, data-protected ASP.NET authentication ticket of a server-side session.

  - id: FriendlyName
    valueType: String
    description: Friendly name of an ASP.NET Data Protection key-ring element (format key-{guid}).

  - id: XmlData
    valueType: String
    description: The raw XML payload of a Data Protection key-ring element.
```

- [ ] **Step 1.3: Create `types/ck-serverSideSession.yaml`** (reuses existing attributes `SubjectId`, `SessionId`, `CreationDateTime`, `ExpirationDateTime` — same reuse pattern as `ck-clientMirror.yaml`):

```yaml
"$schema": "https://schemas.meshmakers.cloud/construction-kit-elements.schema.json"
types:
  - typeId: ServerSideSession
    description: "Duende IdentityServer server-side session. Holds the data-protected authentication ticket server-side so the per-tenant browser cookie only carries a session key (fixes multi-KB cookie bloat)."
    derivedFromCkTypeId: ${System}/Entity
    isFinal: true
    isAbstract: false
    attributes:
      - id: ${this}/SessionKey
        name: SessionKey
      - id: ${this}/Scheme
        name: Scheme
      - id: ${this}/SubjectId
        name: SubjectId
      - id: ${this}/SessionId
        name: SessionId
      - id: ${this}/DisplayName
        name: DisplayName
        isOptional: true
      - id: ${this}/CreationDateTime
        name: CreationDateTime
      - id: ${this}/RenewalDateTime
        name: RenewalDateTime
      - id: ${this}/ExpirationDateTime
        name: ExpirationDateTime
        isOptional: true
      - id: ${this}/Ticket
        name: Ticket
    indexes:
      - indexType: Unique
        fields:
          - attributePaths:
              - SessionKey
      - indexType: Ascending
        fields:
          - attributePaths:
              - SubjectId
      - indexType: Ascending
        fields:
          - attributePaths:
              - SessionId
      - indexType: Ascending
        fields:
          - attributePaths:
              - ExpirationDateTime
```

- [ ] **Step 1.4: Create `types/ck-dataProtectionKey.yaml`**:

```yaml
"$schema": "https://schemas.meshmakers.cloud/construction-kit-elements.schema.json"
types:
  - typeId: DataProtectionKey
    description: "ASP.NET Data Protection key-ring element. Service-global data persisted in the system tenant so every identity pod shares one key ring (replaces the file-system/PVC key store)."
    derivedFromCkTypeId: ${System}/Entity
    isFinal: true
    isAbstract: false
    attributes:
      - id: ${this}/FriendlyName
        name: FriendlyName
      - id: ${this}/XmlData
        name: XmlData
      - id: ${this}/CreationDateTime
        name: CreationDateTime
    indexes:
      - indexType: Unique
        fields:
          - attributePaths:
              - FriendlyName
```

- [ ] **Step 1.5: Create migration 16→17** `src/IdentityServerPersistence/Services/Migrations/ServerSideSessionMigration.cs` (clone of `ClientMirrorMigration.cs`):

```csharp
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services.Migrations;

/// <summary>
/// Migration 16→17: Adds indexes for the new <c>ServerSideSession</c> and
/// <c>DataProtectionKey</c> CK types (server-side session storage + MongoDB-backed
/// Data Protection key ring). No data migration is required — both types are new.
/// </summary>
[Migration(16, 17, IdentityServiceConstants.IdentityMigrationVersionKey,
    "Add indexes for ServerSideSession and DataProtectionKey collections")]
// ReSharper disable once UnusedType.Global
internal class ServerSideSessionMigration(
    ILogger<ServerSideSessionMigration> logger) : IMigration
{
    public async Task<MigrationResult> MigrateAsync(IOctoAdminSession adminSession, ITenantContext tenantContext)
    {
        try
        {
            logger.LogInformation(
                "Updating indexes for tenant {TenantId} (ServerSideSession/DataProtectionKey collections)",
                tenantContext.TenantId);
            await tenantContext.UpdateIndexesAsync(adminSession);
            return MigrationResult.Success();
        }
        catch (Exception e)
        {
            logger.LogError(e,
                "Failed to run ServerSideSession index migration for tenant '{TenantId}'",
                tenantContext.TenantId);
            return MigrationResult.Failure($"Failed to run ServerSideSession index migration: {e.Message}");
        }
    }
}
```

- [ ] **Step 1.6: Build and verify generation**

Run: `dotnet build C:\dev\meshmakers\octo-identity-services\Octo.Identity.sln -c DebugL`
Expected: Build succeeded. Then verify the compiled model contains the new types:

```powershell
Select-String -Path 'C:\dev\meshmakers\octo-identity-services\src\Persistence.IdentityCkModel\bin\DebugL\net10.0\octo-ck-libraries\Persistence.IdentityCkModel\out\ck-system.identity-2.yaml' -Pattern 'typeId: (ServerSideSession|DataProtectionKey)|modelId'
```
Expected: `modelId: System.Identity-2.7.0` + both typeIds present.

- [ ] **Step 1.7: Commit**

```bash
git -C C:\dev\meshmakers\octo-identity-services add -A
git -C C:\dev\meshmakers\octo-identity-services commit -m "feat(ck): System.Identity 2.7.0 - ServerSideSession + DataProtectionKey types, migration 16->17"
```

### Task 2: ServerSideSessionStore (TDD)

**Files:**
- Create: `tests/IdentityServerPersistence.UnitTests/Stores/ServerSideSessionStoreTests.cs`
- Create: `src/IdentityServerPersistence/SystemStores/ServerSideSessionStore.cs`
- Modify: `src/IdentityServerPersistence/Configuration/DependencyInjection/RuntimeEngineBuilderExtensions.cs` (AutoMapper block, after the `PersistedGrant → RtPersistedGrant` map)

- [ ] **Step 2.1: AutoMapper maps.** In `RuntimeEngineBuilderExtensions.cs`, inside the existing `AddAutoMapper(cfg => { ... })` lambda, append after the `cfg.CreateMap<PersistedGrant, RtPersistedGrant>()...` block:

```csharp
            cfg.CreateMap<RtServerSideSession, Duende.IdentityServer.Models.ServerSideSession>()
                .ForMember(dest => dest.Key, opt => opt.MapFrom(src => src.SessionKey))
                .ForMember(dest => dest.Created, opt => opt.MapFrom(src => src.CreationDateTime))
                .ForMember(dest => dest.Renewed, opt => opt.MapFrom(src => src.RenewalDateTime))
                .ForMember(dest => dest.Expires, opt => opt.MapFrom(src => src.ExpirationDateTime));
            cfg.CreateMap<Duende.IdentityServer.Models.ServerSideSession, RtServerSideSession>()
                .ForMember(dest => dest.SessionKey, opt => opt.MapFrom(src => src.Key))
                .ForMember(dest => dest.CreationDateTime, opt => opt.MapFrom(src => src.Created))
                .ForMember(dest => dest.RenewalDateTime, opt => opt.MapFrom(src => src.Renewed))
                .ForMember(dest => dest.ExpirationDateTime, opt => opt.MapFrom(src => src.Expires));
```
(`Scheme`, `SubjectId`, `SessionId`, `DisplayName`, `Ticket` map by convention. Use the fully-qualified Duende type if `ServerSideSession` collides with a using; otherwise add `using Duende.IdentityServer.Models;`.)

- [ ] **Step 2.2: Write failing unit tests** `tests/IdentityServerPersistence.UnitTests/Stores/ServerSideSessionStoreTests.cs` (pattern: `ClientStoreTests` — NSubstitute + `FakeOctoSession`):

```csharp
using AutoMapper;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Fakes;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Stores;

public class ServerSideSessionStoreTests
{
    private readonly ITenantRepository _tenantRepository;
    private readonly IMapper _mapper;
    private readonly ISystemContext _systemContext;
    private readonly ServerSideSessionStore _sut;
    private readonly FakeOctoSession _session;

    public ServerSideSessionStoreTests()
    {
        var multiTenancyResolver = Substitute.For<IMultiTenancyResolverService>();
        _mapper = Substitute.For<IMapper>();
        _systemContext = Substitute.For<ISystemContext>();
        _session = new FakeOctoSession();

        _tenantRepository = Substitute.For<ITenantRepository>();
        _tenantRepository.TenantId.Returns("test-tenant");
        _tenantRepository.GetSessionAsync()
            .Returns(Task.FromResult<IOctoSession>(_session));

        multiTenancyResolver.GetTenantRepository().Returns(_tenantRepository);

        _sut = new ServerSideSessionStore(multiTenancyResolver, _systemContext, _mapper);
    }

    private void SetupSessionLookup(params RtServerSideSession[] sessions)
    {
        var resultSet = Substitute.For<IResultSet<RtServerSideSession>>();
        resultSet.Items.Returns(sessions);
        _tenantRepository.GetRtEntitiesByTypeAsync<RtServerSideSession>(
                _session, Arg.Any<RtEntityQueryOptions>())
            .Returns(resultSet);
    }

    [Fact]
    public async Task GetSessionAsync_UnknownKey_ReturnsNull()
    {
        SetupSessionLookup();

        var result = await _sut.GetSessionAsync("missing-key", CancellationToken.None);

        result.Should().BeNull();
        _session.CommitCount.Should().Be(1);
    }

    [Fact]
    public async Task GetSessionAsync_ExpiredSession_ReturnsNull_WithoutMapping()
    {
        // Expired-but-not-yet-cleaned sessions must NOT authenticate (cleanup runs periodically).
        SetupSessionLookup(new RtServerSideSession
        {
            RtId = OctoObjectId.GenerateNewId(),
            SessionKey = "expired-key",
            ExpirationDateTime = DateTime.UtcNow.AddMinutes(-5)
        });

        var result = await _sut.GetSessionAsync("expired-key", CancellationToken.None);

        result.Should().BeNull();
        _mapper.DidNotReceiveWithAnyArgs().Map<ServerSideSession>(default(RtServerSideSession));
    }

    [Fact]
    public async Task GetSessionAsync_LiveSession_MapsAndReturns()
    {
        var rtSession = new RtServerSideSession
        {
            RtId = OctoObjectId.GenerateNewId(),
            SessionKey = "live-key",
            ExpirationDateTime = DateTime.UtcNow.AddHours(1)
        };
        SetupSessionLookup(rtSession);
        var mapped = new ServerSideSession { Key = "live-key" };
        _mapper.Map<ServerSideSession>(rtSession).Returns(mapped);

        var result = await _sut.GetSessionAsync("live-key", CancellationToken.None);

        result.Should().BeSameAs(mapped);
    }

    [Fact]
    public async Task CreateSessionAsync_InsertsAndCommits()
    {
        var duendeSession = new ServerSideSession { Key = "new-key" };
        var rtSession = new RtServerSideSession { SessionKey = "new-key" };
        _mapper.Map<RtServerSideSession>(duendeSession).Returns(rtSession);

        await _sut.CreateSessionAsync(duendeSession, CancellationToken.None);

        _session.TransactionStartCount.Should().Be(1);
        await _tenantRepository.Received(1).InsertOneRtEntityAsync(_session, rtSession);
        _session.CommitCount.Should().Be(1);
        rtSession.RtId.Should().NotBe(default(OctoObjectId));
    }

    [Fact]
    public async Task UpdateSessionAsync_ExistingSession_ReplacesByRtId()
    {
        var existingRtId = OctoObjectId.GenerateNewId();
        SetupSessionLookup(new RtServerSideSession { RtId = existingRtId, SessionKey = "renew-key" });
        var duendeSession = new ServerSideSession { Key = "renew-key" };
        var replacement = new RtServerSideSession { SessionKey = "renew-key" };
        _mapper.Map<RtServerSideSession>(duendeSession).Returns(replacement);

        await _sut.UpdateSessionAsync(duendeSession, CancellationToken.None);

        await _tenantRepository.Received(1)
            .ReplaceOneRtEntityByIdAsync(_session, existingRtId, replacement);
        _session.CommitCount.Should().Be(1);
    }

    [Fact]
    public async Task DeleteSessionAsync_DeletesByKeyAndCommits()
    {
        await _sut.DeleteSessionAsync("dead-key", CancellationToken.None);

        await _tenantRepository.Received(1).DeleteOneRtEntityAsync<RtServerSideSession>(
            _session, Arg.Any<FieldFilterCriteria>(), DeleteOptions.Erase);
        _session.CommitCount.Should().Be(1);
    }

    [Fact]
    public async Task DeleteSessionsAsync_BySubjectId_DeletesManyAndCommits()
    {
        await _sut.DeleteSessionsAsync(
            new SessionFilter { SubjectId = "subject-1" }, CancellationToken.None);

        await _tenantRepository.Received(1).DeleteManyRtEntitiesAsync<RtServerSideSession>(
            _session, Arg.Any<FieldFilterCriteria>(), DeleteOptions.Erase);
        _session.CommitCount.Should().Be(1);
    }
}
```

- [ ] **Step 2.3: Run tests to verify they FAIL** (type does not exist yet):

Run: `dotnet build C:\dev\meshmakers\octo-identity-services\Octo.Identity.sln -c DebugL`
Expected: compile error `ServerSideSessionStore` not found.

- [ ] **Step 2.4: Implement** `src/IdentityServerPersistence/SystemStores/ServerSideSessionStore.cs`:

```csharp
using AutoMapper;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using NLog;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

/// <summary>
///     Duende server-side session store backed by the CK runtime (MongoDB).
/// </summary>
/// <remarks>
///     Sessions are stored in the per-tenant database resolved from the current HTTP context
///     (same pattern as <see cref="PersistentGrantStore" />): the per-tenant auth cookie
///     (<c>TenantCookieManager</c>) is only presented on requests that run in that tenant's
///     context, so reads and writes naturally hit the right database.
///     The expired-session sweep (<see cref="GetAndRemoveExpiredSessionsAsync" />) is invoked by
///     Duende's background cleanup WITHOUT an HTTP context, so it iterates the system tenant and
///     all child tenants via <see cref="ISystemContext" /> (same pattern as
///     <c>TokenCleanupHostService</c>).
/// </remarks>
public class ServerSideSessionStore(
    IMultiTenancyResolverService multiTenancyResolverService,
    ISystemContext systemContext,
    IMapper mapper)
    : IServerSideSessionStore
{
    private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

    private ITenantRepository TenantRepository => multiTenancyResolverService.GetTenantRepository();

    public async Task<ServerSideSession?> GetSessionAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentValidation.ValidateString(nameof(key), key);

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();
        var rtSession = await GetRtSessionByKeyAsync(TenantRepository, session, key);
        await session.CommitTransactionAsync();

        if (rtSession == null)
        {
            return null;
        }

        // Expired-but-not-yet-cleaned sessions must not authenticate. The periodic cleanup
        // (GetAndRemoveExpiredSessionsAsync) is garbage collection, not the authority.
        if (rtSession.ExpirationDateTime.HasValue && rtSession.ExpirationDateTime.Value <= DateTime.UtcNow)
        {
            return null;
        }

        return mapper.Map<ServerSideSession>(rtSession);
    }

    public async Task CreateSessionAsync(ServerSideSession session, CancellationToken cancellationToken = default)
    {
        ArgumentValidation.ValidateObject(nameof(session), session);

        var rtSession = mapper.Map<RtServerSideSession>(session);
        rtSession.RtId = OctoObjectId.GenerateNewId();

        using var octoSession = await TenantRepository.GetSessionAsync();
        octoSession.StartTransaction();
        await TenantRepository.InsertOneRtEntityAsync(octoSession, rtSession);
        await octoSession.CommitTransactionAsync();
    }

    public async Task UpdateSessionAsync(ServerSideSession session, CancellationToken cancellationToken = default)
    {
        ArgumentValidation.ValidateObject(nameof(session), session);

        using var octoSession = await TenantRepository.GetSessionAsync();
        octoSession.StartTransaction();

        var existing = await GetRtSessionByKeyAsync(TenantRepository, octoSession, session.Key);
        if (existing == null)
        {
            // Renewal of a session that was cleaned up concurrently — recreate it.
            var inserted = mapper.Map<RtServerSideSession>(session);
            inserted.RtId = OctoObjectId.GenerateNewId();
            await TenantRepository.InsertOneRtEntityAsync(octoSession, inserted);
        }
        else
        {
            var replacement = mapper.Map<RtServerSideSession>(session);
            await TenantRepository.ReplaceOneRtEntityByIdAsync(octoSession, existing.RtId, replacement);
        }

        await octoSession.CommitTransactionAsync();
    }

    public async Task DeleteSessionAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentValidation.ValidateString(nameof(key), key);

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var fieldFilterCriteria = FieldFilterCriteria.Create(LogicalOperators.And)
            .FieldEquals(nameof(RtServerSideSession.SessionKey), key);

        await TenantRepository.DeleteOneRtEntityAsync<RtServerSideSession>(session, fieldFilterCriteria,
            DeleteOptions.Erase);

        await session.CommitTransactionAsync();
    }

    public async Task<IReadOnlyCollection<ServerSideSession>> GetSessionsAsync(SessionFilter filter,
        CancellationToken cancellationToken = default)
    {
        ArgumentValidation.ValidateObject(nameof(filter), filter);
        filter.Validate();

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = CreateFilterQueryOptions(filter.SubjectId, filter.SessionId);
        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtServerSideSession>(session, queryOptions);

        await session.CommitTransactionAsync();
        return result.Items.Select(mapper.Map<ServerSideSession>).ToList();
    }

    public async Task DeleteSessionsAsync(SessionFilter filter, CancellationToken cancellationToken = default)
    {
        ArgumentValidation.ValidateObject(nameof(filter), filter);
        filter.Validate();

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var fieldFilterCriteria = FieldFilterCriteria.Create(LogicalOperators.And);
        if (!string.IsNullOrWhiteSpace(filter.SubjectId))
        {
            fieldFilterCriteria.FieldEquals(nameof(RtServerSideSession.SubjectId), filter.SubjectId);
        }
        if (!string.IsNullOrWhiteSpace(filter.SessionId))
        {
            fieldFilterCriteria.FieldEquals(nameof(RtServerSideSession.SessionId), filter.SessionId);
        }

        await TenantRepository.DeleteManyRtEntitiesAsync<RtServerSideSession>(session, fieldFilterCriteria,
            DeleteOptions.Erase);

        await session.CommitTransactionAsync();
    }

    public async Task<IReadOnlyCollection<ServerSideSession>> GetAndRemoveExpiredSessionsAsync(int count,
        CancellationToken cancellationToken = default)
    {
        // Invoked by Duende's background cleanup host — NO HTTP context, so the per-request
        // tenant resolver cannot be used. Sweep the system tenant first, then all child tenants
        // (same pattern as TokenCleanupHostService).
        var removed = new List<ServerSideSession>();

        try
        {
            await CollectExpiredSessionsForTenantAsync(systemContext.GetSystemTenantRepository(), removed, count);

            if (removed.Count >= count || !await systemContext.IsSystemTenantExistingAsync())
            {
                return removed;
            }

            List<OctoTenant> tenantList;
            using (var adminSession = await systemContext.GetAdminSessionAsync())
            {
                adminSession.StartTransaction();
                var tenants = await systemContext.GetChildTenantsAsync(adminSession);
                tenantList = tenants.Items.ToList();
                await adminSession.CommitTransactionAsync();
            }

            foreach (var tenant in tenantList)
            {
                if (removed.Count >= count)
                {
                    break;
                }

                try
                {
                    var tenantRepo = await systemContext.TryFindTenantRepositoryAsync(tenant.TenantId);
                    if (tenantRepo != null)
                    {
                        await CollectExpiredSessionsForTenantAsync(tenantRepo, removed, count);
                    }
                }
                catch (Exception ex)
                {
                    Logger.Error("Exception removing expired sessions for tenant '{TenantId}': {Message}",
                        tenant.TenantId, ex.Message);
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Error("Exception removing expired sessions: {Message}", ex.Message);
        }

        return removed;
    }

    public async Task<QueryResult<ServerSideSession>> QuerySessionsAsync(SessionQuery? filter = null,
        CancellationToken cancellationToken = default)
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = CreateFilterQueryOptions(filter?.SubjectId, filter?.SessionId);
        if (!string.IsNullOrWhiteSpace(filter?.DisplayName))
        {
            queryOptions.FieldFilter(nameof(RtServerSideSession.DisplayName), FieldFilterOperator.Like,
                filter.DisplayName);
        }

        var take = filter is { CountRequested: > 0 } ? filter.CountRequested : 25;
        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtServerSideSession>(session,
            queryOptions, 0, take);

        await session.CommitTransactionAsync();

        var items = result.Items.Select(mapper.Map<ServerSideSession>).ToList();
        return new QueryResult<ServerSideSession>
        {
            Results = items,
            // Single-page result: no continuation token support (admin/diagnostic surface only).
            ResultsToken = null,
            HasPrevResults = false,
            HasNextResults = false,
            TotalCount = items.Count
        };
    }

    private async Task CollectExpiredSessionsForTenantAsync(ITenantRepository tenantRepository,
        List<ServerSideSession> removed, int count)
    {
        using var session = await tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtServerSideSession.ExpirationDateTime), FieldFilterOperator.LessEqualThan,
                DateTime.UtcNow);

        var remaining = count - removed.Count;
        var query = await tenantRepository.GetRtEntitiesByTypeAsync<RtServerSideSession>(session,
            queryOptions, 0, remaining);

        foreach (var rtSession in query.Items)
        {
            try
            {
                await tenantRepository.DeleteOneRtEntityByRtIdAsync<RtServerSideSession>(session,
                    rtSession.RtId, DeleteOptions.Erase);
                removed.Add(mapper.Map<ServerSideSession>(rtSession));
            }
            catch (OperationFailedException ex)
            {
                Logger.Debug(
                    "Concurrency exception removing expired session '{RtId}' for tenant '{TenantId}': {Message}",
                    rtSession.RtId, tenantRepository.TenantId, ex.Message);
            }
        }

        await session.CommitTransactionAsync();
    }

    private static RtEntityQueryOptions CreateFilterQueryOptions(string? subjectId, string? sessionId)
    {
        var queryOptions = RtEntityQueryOptions.Create();
        if (!string.IsNullOrWhiteSpace(subjectId))
        {
            queryOptions.FieldFilter(nameof(RtServerSideSession.SubjectId), FieldFilterOperator.Equals, subjectId);
        }
        if (!string.IsNullOrWhiteSpace(sessionId))
        {
            queryOptions.FieldFilter(nameof(RtServerSideSession.SessionId), FieldFilterOperator.Equals, sessionId);
        }
        return queryOptions;
    }

    private static async Task<RtServerSideSession?> GetRtSessionByKeyAsync(ITenantRepository repository,
        IOctoSession session, string key)
    {
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtServerSideSession.SessionKey), FieldFilterOperator.Equals, key);

        var result = await repository.GetRtEntitiesByTypeAsync<RtServerSideSession>(session, queryOptions);
        return result.Items.FirstOrDefault();
    }
}
```

**Compiler-truth caveats (resolve while implementing, do not guess):**
- Exact `IServerSideSessionStore` parameter names/optionality: implement the interface via IDE "Implement interface" and keep our bodies. The XML doc shows `QuerySessionsAsync(SessionQuery, CancellationToken)`; if the compiler demands `(SessionQuery? filter, CancellationToken ct)` without defaults, match it.
- `ArgumentValidation.ValidateObject` — if that helper does not exist in `Meshmakers.Common.Shared`, use `ArgumentNullException.ThrowIfNull(...)` instead (check `PersistentGrantStore`'s usings for what's available).
- `OctoTenant` type/namespace: copy the exact using set from `TokenCleanupHostService.cs` for the child-tenant iteration.
- If `ServerSideSession.Expires` is `DateTime?` and the generated `RtServerSideSession.ExpirationDateTime` is `DateTime?` (isOptional), the maps are symmetric. Verify by building.

- [ ] **Step 2.5: Run unit tests**

Run: `dotnet test C:\dev\meshmakers\octo-identity-services\tests\IdentityServerPersistence.UnitTests\IdentityServerPersistence.UnitTests.csproj -c DebugL --filter "FullyQualifiedName~ServerSideSessionStoreTests"`
Expected: all PASS.

- [ ] **Step 2.6: Commit**

```bash
git -C C:\dev\meshmakers\octo-identity-services add -A
git -C C:\dev\meshmakers\octo-identity-services commit -m "feat(identity): ServerSideSessionStore backed by CK runtime (Duende IServerSideSessionStore)"
```

### Task 3: DataProtectionKeyStore — IXmlRepository with seed-once import

**Files:**
- Create: `src/IdentityServerPersistence/SystemStores/DataProtectionKeyStore.cs`
- Test: covered by integration tests (Task 5) — the class is a thin sync-over-async shim around the system-tenant repository; unit-mocking `ISystemContext`+scope adds little value over the real-Mongo test.

- [ ] **Step 3.1: Implement** `src/IdentityServerPersistence/SystemStores/DataProtectionKeyStore.cs`:

```csharp
using System.Xml.Linq;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using IdentityServerPersistence.Configuration.Options;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NLog;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

/// <summary>
///     ASP.NET Data Protection key-ring repository backed by the CK runtime (MongoDB).
/// </summary>
/// <remarks>
///     The key ring is service-global (shared by all pods, used across all tenants), so it is
///     stored in the SYSTEM tenant database via <see cref="ISystemContext" /> — the per-request
///     tenant resolver cannot be used because Data Protection runs outside any HTTP context.
///     <para>
///     Zero-logout migration: when the store is EMPTY and the legacy file path
///     (<c>Identity:DataProtectionKeysPath</c>) still exists (old chart still mounts the PVC),
///     all key-*.xml files are imported ONCE so existing cookies/sessions keep decrypting.
///     </para>
///     <para>
///     <see cref="IXmlRepository" /> is synchronous by contract; the rare calls (key-ring load on
///     first use, key creation/rotation every ~90 days) make sync-over-async acceptable here.
///     </para>
/// </remarks>
public class DataProtectionKeyStore(
    IServiceScopeFactory serviceScopeFactory,
    IOptions<OctoIdentityServicesOptions> identityOptions) : IXmlRepository
{
    private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
    private readonly object _seedLock = new();
    private bool _seedAttempted;

    public IReadOnlyCollection<XElement> GetAllElements()
    {
        return GetAllElementsAsync().GetAwaiter().GetResult();
    }

    public void StoreElement(XElement element, string friendlyName)
    {
        ArgumentNullException.ThrowIfNull(element);
        var name = string.IsNullOrWhiteSpace(friendlyName)
            ? $"key-{Guid.NewGuid():D}"
            : friendlyName;
        StoreElementAsync(element, name).GetAwaiter().GetResult();
    }

    private async Task<IReadOnlyCollection<XElement>> GetAllElementsAsync()
    {
        using var scope = serviceScopeFactory.CreateScope();
        var systemContext = scope.ServiceProvider.GetRequiredService<ISystemContext>();
        var repository = systemContext.GetSystemTenantRepositoryAsAdmin();

        var keys = await LoadAllKeysAsync(repository);

        if (keys.Count == 0)
        {
            await TrySeedFromLegacyFilesAsync(repository);
            keys = await LoadAllKeysAsync(repository);
        }

        return keys.Select(k => XElement.Parse(k.XmlData)).ToList();
    }

    private static async Task<List<RtDataProtectionKey>> LoadAllKeysAsync(ITenantRepository repository)
    {
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        var result = await repository.GetRtEntitiesByTypeAsync<RtDataProtectionKey>(session,
            RtEntityQueryOptions.Create());
        await session.CommitTransactionAsync();
        return result.Items.ToList();
    }

    private async Task StoreElementAsync(XElement element, string friendlyName)
    {
        using var scope = serviceScopeFactory.CreateScope();
        var systemContext = scope.ServiceProvider.GetRequiredService<ISystemContext>();
        var repository = systemContext.GetSystemTenantRepositoryAsAdmin();

        await StoreElementInternalAsync(repository, element, friendlyName);
    }

    private static async Task StoreElementInternalAsync(ITenantRepository repository, XElement element,
        string friendlyName)
    {
        try
        {
            using var session = await repository.GetSessionAsync();
            session.StartTransaction();

            var existing = await repository.GetRtEntitiesByTypeAsync<RtDataProtectionKey>(session,
                RtEntityQueryOptions.Create()
                    .FieldFilter(nameof(RtDataProtectionKey.FriendlyName), FieldFilterOperator.Equals,
                        friendlyName));
            if (existing.Items.Any())
            {
                // Same key already persisted (concurrent first-boot of multiple pods) — done.
                await session.CommitTransactionAsync();
                return;
            }

            var rtKey = new RtDataProtectionKey
            {
                RtId = OctoObjectId.GenerateNewId(),
                FriendlyName = friendlyName,
                XmlData = element.ToString(SaveOptions.DisableFormatting),
                CreationDateTime = DateTime.UtcNow
            };
            await repository.InsertOneRtEntityAsync(session, rtKey);
            await session.CommitTransactionAsync();
        }
        catch (Exception ex)
        {
            // Unique index on FriendlyName: a concurrent pod won the race — the key IS persisted,
            // which is all the Data Protection stack needs. Anything else is a real error.
            Logger.Warn("Storing data protection key '{FriendlyName}' hit a conflict ({Message}); verifying",
                friendlyName, ex.Message);

            using var session = await repository.GetSessionAsync();
            session.StartTransaction();
            var verify = await repository.GetRtEntitiesByTypeAsync<RtDataProtectionKey>(session,
                RtEntityQueryOptions.Create()
                    .FieldFilter(nameof(RtDataProtectionKey.FriendlyName), FieldFilterOperator.Equals,
                        friendlyName));
            await session.CommitTransactionAsync();

            if (!verify.Items.Any())
            {
                throw;
            }
        }
    }

    private async Task TrySeedFromLegacyFilesAsync(ITenantRepository repository)
    {
        lock (_seedLock)
        {
            if (_seedAttempted)
            {
                return;
            }
            _seedAttempted = true;
        }

        var legacyPath = identityOptions.Value.DataProtectionKeysPath;
        if (string.IsNullOrWhiteSpace(legacyPath) || !Directory.Exists(legacyPath))
        {
            return;
        }

        var keyFiles = Directory.GetFiles(legacyPath, "key-*.xml");
        if (keyFiles.Length == 0)
        {
            return;
        }

        Logger.Info("Seeding {Count} data protection keys from legacy path '{Path}' into MongoDB",
            keyFiles.Length, legacyPath);

        foreach (var keyFile in keyFiles)
        {
            try
            {
                var element = XElement.Parse(await File.ReadAllTextAsync(keyFile));
                var friendlyName = Path.GetFileNameWithoutExtension(keyFile);
                await StoreElementInternalAsync(repository, element, friendlyName);
            }
            catch (Exception ex)
            {
                Logger.Error("Failed to seed data protection key from '{File}': {Message}", keyFile, ex.Message);
            }
        }
    }
}
```

**Compiler-truth caveats:** `lock` + `await` cannot mix — the lock only guards the `_seedAttempted` flag (no await inside), as written. If `RtDataProtectionKey.CreationDateTime` is generated as `DateTime?`, assignment still compiles. Check `FieldFilterOperator`/`RtEntityQueryOptions` usings against `PersistentGrantStore`.

- [ ] **Step 3.2: Build**

Run: `dotnet build C:\dev\meshmakers\octo-identity-services\Octo.Identity.sln -c DebugL`
Expected: Build succeeded.

- [ ] **Step 3.3: Commit**

```bash
git -C C:\dev\meshmakers\octo-identity-services add -A
git -C C:\dev\meshmakers\octo-identity-services commit -m "feat(identity): MongoDB-backed DataProtection key ring with seed-once import from legacy file path"
```

### Task 4: Program.cs wiring

**Files:**
- Modify: `src/IdentityServices/Program.cs` (lines 88-94 DP block; identityServerBuilder chain ~line 163-171; ConfigureApplicationCookie ~line 178-183)
- Modify: `src/IdentityServerPersistence/Configuration/Options/OctoIdentityServicesOptions.cs` (doc comment)

- [ ] **Step 4.1: Replace the conditional DP block** (current lines 88-94) with always-on wiring:

```csharp
    // ASP.NET Data Protection: the key ring is persisted in MongoDB (system tenant) — ALWAYS ON,
    // shared by all pods. Identity:DataProtectionKeysPath is no longer a persistence target; if it
    // is set and contains legacy key-*.xml files (old chart still mounts the PVC), they are
    // imported ONCE by DataProtectionKeyStore so existing sessions survive the migration.
    builder.Services.AddSingleton<IXmlRepository, DataProtectionKeyStore>();
    builder.Services.AddOptions<KeyManagementOptions>()
        .Configure<IXmlRepository>((options, repository) => options.XmlRepository = repository);
    builder.Services.AddDataProtection()
        .SetApplicationName("OctoIdentityServices");
```

Add usings at top of Program.cs: `using Microsoft.AspNetCore.DataProtection.KeyManagement;` and `using Microsoft.AspNetCore.DataProtection.Repositories;` (keep the existing `Microsoft.AspNetCore.DataProtection` using — `AddDataProtection`/`SetApplicationName` need it).

- [ ] **Step 4.2: Enable server-side sessions.** In the `identityServerBuilder` chain, after `.AddProfileService<UserProfileService>()` add:

```csharp
        .AddServerSideSessions<ServerSideSessionStore>()
```

(extension lives in namespace `Microsoft.Extensions.DependencyInjection` — no new using needed; `ServerSideSessionStore` needs `using IdentityServerPersistence.SystemStores;` which Program.cs already has for `PersistentGrantStore`.)

- [ ] **Step 4.3: Explicit cookie lifetime.** In `ConfigureApplicationCookie`:

```csharp
    builder.Services.ConfigureApplicationCookie(o =>
    {
        o.CookieManager = tenantCookieManager;
        o.SlidingExpiration = true;
        // With server-side sessions this bounds BOTH the cookie and the session record.
        // Explicit (was: 14-day framework default) — sliding, so active users stay signed in.
        o.ExpireTimeSpan = TimeSpan.FromDays(7);
    });
```

- [ ] **Step 4.4: Update `OctoIdentityServicesOptions.DataProtectionKeysPath` doc comment:**

```csharp
    /// <summary>
    /// LEGACY/SEED-ONLY: former filesystem path for ASP.NET Data Protection keys.
    /// Keys are now always persisted in MongoDB (system tenant). When this path is set and
    /// contains key-*.xml files, they are imported once at first key-ring load so existing
    /// sessions survive the migration. Safe to remove after all environments have migrated.
    /// </summary>
    public string? DataProtectionKeysPath { get; set; }
```

- [ ] **Step 4.5: Build + run full unit test suite**

Run: `dotnet build C:\dev\meshmakers\octo-identity-services\Octo.Identity.sln -c DebugL`
Expected: Build succeeded (warnings-as-errors on).

- [ ] **Step 4.6: Commit**

```bash
git -C C:\dev\meshmakers\octo-identity-services add -A
git -C C:\dev\meshmakers\octo-identity-services commit -m "feat(identity): enable Duende server-side sessions + always-on MongoDB DataProtection key ring"
```

### Task 5: Integration tests (real Mongo via Testcontainers)

**Files:**
- Create: `tests/IdentityServices.IntegrationTests/Persistence/ServerSideSessionStoreIntegrationTests.cs`
- Create: `tests/IdentityServices.IntegrationTests/Persistence/DataProtectionKeyStoreIntegrationTests.cs`

Pattern: `[Collection("Sequential")]` + `IClassFixture<IdentityServicesFixture>`; every `[Fact]` starts with `await _fixture.InitializeAsync();` then `await EnsureSystemSetupAsync();` (which runs `IDefaultConfigurationCreatorService.SetupAsync(systemTenantId)` → installs CK model 2.7.0 incl. the new types + runs migration 16→17). Resolve the REAL `IMapper` from the fixture (`_fixture.GetService<IMapper>()`) so the AutoMapper config is exercised. `IMultiTenancyResolverService` has no HTTP context in tests — stub it to return `systemContext.GetSystemTenantRepositoryAsAdmin()`:

```csharp
internal sealed class FixedTenantResolver(ITenantRepository repository) : IMultiTenancyResolverService
{
    public ITenantRepository GetTenantRepository() => repository;
    public string GetTenantId() => repository.TenantId;
}
```

- [ ] **Step 5.1: `ServerSideSessionStoreIntegrationTests`** — facts (full round-trips against Mongo):
  - `CreateAndGet_RoundTrips_AllProperties`: create `ServerSideSession { Key, Scheme = "idsrv", SubjectId, SessionId, Created/Renewed = UtcNow (truncate to ms), Expires = UtcNow.AddHours(1), Ticket = "ticket-payload" }` → `GetSessionAsync` returns equivalent (FluentAssertions `BeEquivalentTo` with DateTime tolerance `.Using<DateTime>(ctx => ctx.Subject.Should().BeCloseTo(ctx.Expectation, TimeSpan.FromSeconds(1)))`).
  - `GetSessionAsync_Expired_ReturnsNull`: create with `Expires = UtcNow.AddMinutes(-1)` → null.
  - `UpdateSessionAsync_RenewsTicketAndExpiry`: create → update with new Ticket/Expires → get returns updated values, and only ONE document exists for the key.
  - `DeleteSessionAsync_RemovesDocument`: create → delete → get returns null.
  - `GetSessionsAsync_FiltersBySubject`: create 2 sessions different subjects → filter SubjectId returns only matching.
  - `GetAndRemoveExpiredSessionsAsync_RemovesAndReturnsExpired_KeepsLive`: create 1 expired + 1 live → call with count 10 → returns the expired one, live still retrievable, expired gone.
  - Construct the store with `new ServerSideSessionStore(new FixedTenantResolver(systemContext.GetSystemTenantRepositoryAsAdmin()), systemContext, _fixture.GetService<IMapper>())`.

- [ ] **Step 5.2: `DataProtectionKeyStoreIntegrationTests`** — facts:
  - `StoreAndGetAll_RoundTripsXml`: `StoreElement(XElement.Parse("<key id=\"k1\">payload</key>"), "key-test-1")` → `GetAllElements()` contains an element with same name+content.
  - `StoreElement_SameFriendlyName_Twice_IsIdempotent`: store twice → `GetAllElements()` has exactly one element with that name.
  - `GetAllElements_EmptyStore_SeedsFromLegacyPath`: write 2 fake `key-*.xml` files into a temp dir, set options `DataProtectionKeysPath = tempDir` → first `GetAllElements()` returns both, and a second store instance (fresh `_seedAttempted`) still sees them from Mongo after deleting the temp dir.
  - Constructing the store needs an `IServiceScopeFactory` whose scope resolves `ISystemContext` — use `_fixture.Provider!.GetRequiredService<IServiceScopeFactory>()` (the fixture's root provider has `ISystemContext` registered). Options: `Options.Create(new OctoIdentityServicesOptions { IdentityServerLicenseKey = "test", AutoMapperLicenseKey = "test", DataProtectionKeysPath = tempDir })`.
  - NOTE: tests must be tolerant of pre-existing `DataProtectionKey` docs in the shared fixture DB (system tenant is recreated per fixture, so a fresh class fixture = clean state; keep the seed test FIRST or assert on specific FriendlyNames rather than counts).

- [ ] **Step 5.3: Run integration tests**

Run: `dotnet test C:\dev\meshmakers\octo-identity-services\tests\IdentityServices.IntegrationTests\IdentityServices.IntegrationTests.csproj -c DebugL --filter "FullyQualifiedName~ServerSideSessionStoreIntegrationTests|FullyQualifiedName~DataProtectionKeyStoreIntegrationTests"`
Expected: all PASS (requires Docker for Testcontainers — kind cluster does not interfere; Testcontainers maps a random host port).

- [ ] **Step 5.4: Full suite + commit**

Run: `dotnet test C:\dev\meshmakers\octo-identity-services\Octo.Identity.sln -c DebugL`
Expected: all PASS.

```bash
git -C C:\dev\meshmakers\octo-identity-services add -A
git -C C:\dev\meshmakers\octo-identity-services commit -m "test(identity): integration coverage for server-side sessions + DP key ring (Testcontainers Mongo)"
```

### Task 6: Documentation (mandatory per repo CLAUDE.md)

- [ ] **Step 6.1:** `CLAUDE.md`: rewrite the "Data Protection Key Persistence" section → MongoDB-backed always-on key ring (system tenant, `DataProtectionKeyStore`), `DataProtectionKeysPath` = legacy seed source only. Update the CK model version mention (System.Identity-2.7.0, schema/migration 17) and add `ServerSideSession`/`DataProtectionKey` to the persistence notes + mention `.AddServerSideSessions<ServerSideSessionStore>()` and the per-tenant-cookie interaction (cookie now carries only a session key; `TenantCookieManager` naming unchanged).
- [ ] **Step 6.2:** `docs/persistence.md` + `docs/authentication.md`: add a "Server-side sessions" subsection (why: cookie bloat broke loopback OAuth callbacks; what: ticket server-side, cookie = key; cleanup semantics: expired-is-a-miss + Duende sweep) and update the DP key section.
- [ ] **Step 6.3:** Commit: `docs(identity): server-side sessions + MongoDB DP key ring`

### Task 7: Helm chart — remove dataProtection feature (octo-helm-core)

**Branch:** create `dev/remove-identity-data-protection-toggle` in `C:\dev\meshmakers\octo-helm-core`. **No push.**

- [ ] **Step 7.1: BASELINE renders** (before any edit) — for each cluster `prod-1, prod-2, staging-1, test-2`:

```powershell
helm template octo-mesh C:\dev\meshmakers\octo-helm-core\src\octo-mesh `
  -f C:\dev\meshmakers\deployment\octo-mesh-deployment\base\values-octo-mesh.yaml `
  -f C:\dev\meshmakers\deployment\octo-mesh-deployment\clusters\<CLUSTER>\values-octo-mesh.yaml `
  > C:\Users\reimar\AppData\Local\Temp\claude\helm-baseline-<CLUSTER>.yaml
```
Expected: renders without error (if a required value is missing, add the minimal `--set` the error demands and keep it identical for the after-render).

- [ ] **Step 7.2: Edit chart** (all in `src/octo-mesh/`):
  1. DELETE `templates/pvc.yaml` (whole file — it is 100% dataProtection).
  2. `templates/_env.tpl`: delete the 4 lines 90-93 (`{{- if .global.Values.services.identity.dataProtection.enabled }}` / `- name: OCTO_IDENTITY__DataProtectionKeysPath` / `value: "/var/dpapi-keys"` / `{{- end }}`).
  3. `templates/deployment.yaml` line 26: `{{- if or (and $svc.dataProtection $svc.dataProtection.enabled) $svc.recreateStrategy }}` → `{{- if $svc.recreateStrategy }}` — **KEEP the recreateStrategy arm (bot/RabbitMQ exclusive queues)**.
  4. `templates/deployment.yaml` line 139: drop the `(and $svc.dataProtection $svc.dataProtection.enabled)` term → `{{- if or $svc.signingKey $svc.pod.volumeMounts $global.Values.secrets.rootCa }}`; delete the mount entry (lines 149-152: `{{- if and $svc.dataProtection ... }}` block with `data-protection-keys` / `/var/dpapi-keys`).
  5. `templates/deployment.yaml` line 158: same `or`-term removal → `{{- if or $svc.signingKey $svc.pod.volumes $global.Values.secrets.rootCa }}`; delete the PVC volume entry (lines 169-173).
  6. `values.yaml`: delete lines 100-110 (the 4 comment lines + `dataProtection:` block).
  7. `README.md`: delete lines 72-85 ("Enable Data Protection key persistence..." section).

- [ ] **Step 7.3: Verify renders after edit** — same 4 commands into `helm-after-<CLUSTER>.yaml`. Assertions:

```powershell
# 1) all four render without nil-pointer errors (CRITICAL: prod-2/staging-1 pass no dataProtection key at all)
# 2) no dataProtection residue:
Select-String -Path C:\Users\reimar\AppData\Local\Temp\claude\helm-after-*.yaml -Pattern 'dpapi|data-protection|DataProtection'   # expect: no matches
# 3) bot keeps Recreate:
Select-String -Path C:\Users\reimar\AppData\Local\Temp\claude\helm-after-prod-1.yaml -Pattern 'type: Recreate' -Context 12,0      # expect: exactly the bot-services deployment
# 4) identity loses Recreate + PVC + mount; everything else identical:
Compare-Object (Get-Content ...baseline-prod-1.yaml) (Get-Content ...after-prod-1.yaml)  # expect ONLY dataProtection-related lines
```

- [ ] **Step 7.4: Commit** (octo-helm-core): `feat(octo-mesh)!: remove identity dataProtection toggle/PVC — key ring now lives in MongoDB (identity >= <version>)`

### Task 8: deployment repo — strip dataProtection values

**Branch:** create `dev/remove-identity-data-protection-toggle` in `C:\dev\meshmakers\deployment\octo-mesh-deployment`. **No push.**

- [ ] **Step 8.1:** Delete `dataProtection` blocks: `base/values-octo-mesh.yaml` lines 40-42 (3 lines), `clusters/prod-1/values-octo-mesh.yaml` lines 16-19 (4 lines), `clusters/test-2/values-octo-mesh.yaml` lines 87-91 (5 lines INCLUDING the `# Proxmox-backed...` comment). `staging-1`/`prod-2`: no edit (verified: no dataProtection key).
- [ ] **Step 8.2:** Re-run the 4 `helm template` renders from Task 7.3 with the EDITED values files → still clean, zero dataProtection matches.
- [ ] **Step 8.3:** Commit: `chore: drop identity dataProtection values (chart no longer supports it; key ring in MongoDB)` — body must note the shipping order (identity image first) and the post-cutover manual PVC deletion runbook step (`kubectl -n <ns> delete pvc <release>-identity-data-protection` per cluster, after Mongo ring verified).

### Task 9: Local end-to-end verification

- [ ] **Step 9.1:** `Invoke-Build -repositoryPath ./octo-identity-services -configuration DebugL` then `Start-Octo -nonInteractive $true` (octo-devtools wrapper). Watch `logFiles/IdentityServices.log` for: CK model 2.7.0 import per tenant, migration 16→17, no DP errors.
- [ ] **Step 9.2:** Playwright: open `https://localhost:4200`, log into tenant `octosystem`, then tenant `test`. After login assert via browser cookies: every `.AspNetCore.Identity.Application.<tenant>` cookie value is **< ~400 chars** (session key, not a 3 KB ticket).
- [ ] **Step 9.3:** Mongo (kind cluster, localhost:27017): `ServerSideSession` documents exist in the tenants' DBs; `DataProtectionKey` document(s) exist in the system tenant DB.
- [ ] **Step 9.4:** Restart ONLY identity (kill its dotnet process, `Start-Octo -nonInteractive $true` again or rerun the service): reload the SPA → still logged in (key ring survived in Mongo; session record still valid). THIS is the headline proof.
- [ ] **Step 9.5:** Seed-import proof: stop identity; export the `DataProtectionKey` docs; drop them; place equivalent `key-*.xml` files in a temp dir; set `OCTO_IDENTITY__DataProtectionKeysPath=<tempdir>`; start identity → docs re-appear in Mongo (imported), existing browser session still works.

### Done criteria (maps to the session goal)
1. All identity tests green (`dotnet test ... -c DebugL`).
2. Local stack running; two-tenant login works; cookies are tiny; sessions + key ring visibly in Mongo; identity restart does NOT log the user out.
3. `helm template` of the modified chart against all four real cluster value files renders clean, no dataProtection residue, bot keeps `Recreate` — the "plausibly works for deployments" evidence.
4. Nothing pushed; all three repos on local `dev/*` branches awaiting Reimar's review.

## Self-Review Notes
- Type/name consistency: `RtServerSideSession.SessionKey/Scheme/SubjectId/SessionId/DisplayName/CreationDateTime/RenewalDateTime/ExpirationDateTime/Ticket`; `RtDataProtectionKey.FriendlyName/XmlData/CreationDateTime` — match the YAML `name:` fields exactly; AutoMapper member configs match these.
- The store implementations intentionally mirror `PersistentGrantStore`'s transaction idiom; deviations (expired-is-a-miss, recreate-on-missing-update) are commented in code.
- Spec coverage check: server-side sessions ✔ (Tasks 1,2,4,5), always-on Mongo DP ✔ (1,3,4,5), zero-logout seed ✔ (3, 9.5), chart deletion incl. bot-Recreate trap + nil-guard atomicity ✔ (7), values cleanup ✔ (8), shipping order documented ✔ (8.3), docs ✔ (6).
