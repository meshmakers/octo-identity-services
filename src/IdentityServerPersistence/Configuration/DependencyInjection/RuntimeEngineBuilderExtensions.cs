using IdentityServerPersistence.AutoMap;
using IdentityServerPersistence.Configuration.DependencyInjection;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.Services.Admin;
using IdentityServerPersistence.Services.Login;
using IdentityServerPersistence.Services.SelfService;
using IdentityServerPersistence.SystemStores;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Meshmakers.Octo.Common.DistributionEventHub.Configuration;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Runtime.Contracts.Blueprints;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Runtime.Engine.Configuration.DependencyInjection;
using Meshmakers.Octo.Services.Infrastructure;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.DependencyInjection;

public static class RuntimeEngineBuilderExtensions
{
    public static IRuntimeEngineBuilder AddOctoIdentityPersistence(
        this IRuntimeEngineBuilder builder,
        Action<OctoSystemConfiguration>? setupSystemConfigurationAction = null,
        Action<IdentityOptions>? setupAction = null, Action<IDistributionEventHubConfiguration>? configureDistributionEventHub = null)
    {
        if (setupSystemConfigurationAction != null)
        {
            builder.Services.Configure(setupSystemConfigurationAction);
        }

        // Adding dependent octo modules
        builder.Services.AddOctoServiceInfrastructure("IdentityService", configureDistributionEventHub);
        builder.AddMongoDbRuntimeRepository();

        // Persist blueprint installation + history rows in MongoDB (RtEntity_SystemBlueprintInstallation
        // and RtEntity_SystemBlueprintHistory). Without this the engine defaults to
        // InMemoryTenantBlueprintInstallations, which silently drops the rows on every restart —
        // engine logs still report "1 blueprints installed" but no MongoDB row lands, breaking
        // Studio's blueprint listing and idempotent re-apply detection. Mirrors what
        // CommunicationController / AiServices / AssetRepo / PlatformServices already register
        // in their respective Program.cs; Identity was the outlier.
        builder.AddMongoBlueprintSupport();

        // Add the construction kits as embedded repository
        builder.Services.AddCkModelSystemIdentityV2();

        // Phase 3 PR #3: Identity-specific blueprint variable provider. Replaces the engine's
        // default IBlueprintVariableProvider (which is TryAdded inside AddRuntimeEngine) with
        // a richer one that exposes octo.identity.authorityUrl and octo.identity.refineryStudioUrl
        // in addition to the standard octo.* variables. Must be a plain AddTransient (not Try*) so
        // it wins over the engine default; BlueprintService consumes the SINGULAR registration
        // and the last add wins.
        builder.Services.AddTransient<IBlueprintVariableProvider, IdentityBlueprintVariableProvider>();

        // Add services of Identity module
        builder.Services
            .AddScopedMultipleInterfaces<DefaultConfigurationCreatorService, IDefaultConfigurationCreatorService,
                IConfigurationService>();

        builder.Services.AddScoped<IOctoClientStore, ClientStore>();
        builder.Services.AddScoped<IOctoResourceStore, ResourceStore>();
        builder.Services.AddScoped<IOctoPersistentGrantStore, PersistentGrantStore>();
        builder.Services.AddScoped<IOctoIdentityProviderStore, IdentityProviderStore>();
        builder.Services.AddScoped<IExternalTenantUserMappingStore, ExternalTenantUserMappingStore>();
        builder.Services.AddScoped<IGroupStore, GroupStore>();
        builder.Services.AddScoped<IDataPermissionStore, DataPermissionStore>();
        builder.Services.AddScoped<IGroupRoleResolver, GroupRoleResolver>();
        builder.Services.AddScoped<IClientRoleStore, ClientRoleStore>();
        builder.Services.AddScoped<ICrossTenantAuthenticationService, CrossTenantAuthenticationService>();
        builder.Services.AddScoped<ICrossTenantUserProvisioningService, CrossTenantUserProvisioningService>();
        builder.Services.AddScoped<IAllowedTenantsResolver, AllowedTenantsResolver>();
        builder.Services.AddScoped<IEmailDomainGroupRuleStore, EmailDomainGroupRuleStore>();
        builder.Services.AddScoped<ILoginGroupAssignmentService, LoginGroupAssignmentService>();
        // AB#5124: auto-provision the (EntraIdObjectId, oid) → user verified-identifier binding on
        // EntraID login, so the mesh adapter can resolve a Teams sender's AAD object id to this user.
        builder.Services
            .AddScoped<IEntraIdVerifiedIdentifierEnrollmentService, EntraIdVerifiedIdentifierEnrollmentService>();
        builder.Services.AddScoped<ITenantDiscoveryService, TenantDiscoveryService>();
        builder.Services.AddScoped<IClientMirrorProvisioningService, ClientMirrorProvisioningService>();
        // AB#5026 delegation ("on-behalf-of"): the protocol-free policy behind OnBehalfOfProcessor.
        builder.Services.AddScoped<IDelegatedIdentityResolver, DelegatedIdentityResolver>();
        // AB#5114 impersonation: the MayActAs edge store and the protocol-free policy behind
        // ImpersonationProcessor (and the on-behalf-of requested_client_id extension).
        builder.Services.AddScoped<IClientImpersonationStore, ClientImpersonationStore>();
        builder.Services.AddScoped<IImpersonatedIdentityResolver, ImpersonatedIdentityResolver>();
        // AB#5122 verified external identifier directory: resolves a verified external identifier
        // (phone / e-mail / EntraID oid / cert fingerprint) to a user with two-dimension trust
        // (effective = min(enrollment, message)). The write side is the seam the sibling enrollment
        // WIs (AB#5123–5126) call.
        builder.Services.AddScoped<IVerifiedIdentifierResolver, VerifiedIdentifierResolver>();

        // AB#5125 admin-managed e-mail verified whitelist: a tenant admin binds an e-mail address to a
        // user (Source = Admin, EnrollmentTrust = Strong) through the AB#5122 directory. The
        // per-message DKIM/DMARC trust is evaluated on the mesh-adapter ingest side and capped by
        // min() at the verified-caller directory, so a whitelisted address never authorizes an
        // elevated operation on a spoofable (no-DKIM) mail.
        builder.Services.AddScoped<IAdminEmailBindingService, AdminEmailBindingService>();

        // AB#5123 self-service "My identities": the signed-in user manages their OWN strong channel
        // identifiers (phone via OTP, client certificate) with no admin in the loop, writing into the
        // AB#5122 directory with Source = SelfService. The OTP challenge is persisted (hashed, with an
        // expiry + attempt budget) in the existing per-user token store; delivery is abstracted behind
        // IOtpDeliveryChannel.
        builder.Services.TryAddSingleton(TimeProvider.System);
        builder.Services.AddScoped<IOtpChallengeStore, UserTokenOtpChallengeStore>();

        // AB#5134 Signal OTP delivery: when the signal-cli-rest-api bridge is configured
        // (SignalBridge:ApiUrl non-empty) the real SignalRestOtpDeliveryChannel delivers the phone OTP
        // over the same bridge the mesh adapter's SignalSender node uses; otherwise the clearly-marked
        // LoggingOtpDeliveryChannel stub (with its loud warning) stays the Signal channel so dev without
        // a bridge keeps working. Exactly ONE IOtpDeliveryChannel of Kind=Signal is registered (the
        // OTP service dispatches by Kind), decided from the bound SignalBridgeOptions at resolve time.
        // SignalBridgeOptions is bound from the "SignalBridge" config section in Program.cs (this
        // engine-builder extension has no IConfiguration; IOptions<> resolves to defaults — ApiUrl
        // empty → stub — when the section is absent).
        builder.Services.AddHttpClient(SignalRestOtpDeliveryChannel.HttpClientName);
        builder.Services.AddSingleton<IOtpDeliveryChannel>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<SignalBridgeOptions>>().Value;
            return string.IsNullOrWhiteSpace(options.ApiUrl)
                ? ActivatorUtilities.CreateInstance<LoggingOtpDeliveryChannel>(sp)
                : ActivatorUtilities.CreateInstance<SignalRestOtpDeliveryChannel>(sp);
        });

        builder.Services.AddScoped<ISelfServiceIdentifierService, SelfServiceIdentifierService>();

        builder.Services.AddSingleton<AttributeStringValueListConverter>();
        builder.Services.AddAutoMapper(cfg =>
        {
            cfg.CreateMap<ICollection<string>, IAttributeValueList<string>>()
                .ConvertUsing<AttributeStringValueListConverter>();

            cfg.CreateMap<RtRole, RoleDto>()
                .ForMember(dest => dest.Id, opt => opt.MapFrom(src => src.RtId))
                .ForMember(dest => dest.Name, opt => opt.MapFrom(src => src.Name))
                .ReverseMap()
                .ForMember(dest => dest.RtId, x => x.Ignore())
                .ForMember(dest => dest.CkTypeId, x => x.Ignore());

            cfg.CreateMap<RtUser, UserDto>()
                .ForMember(dest => dest.UserId, opt => opt.MapFrom(src => src.RtId))
                .ForMember(dest => dest.Name, opt => opt.MapFrom(src => src.UserName))
                .ForMember(dest => dest.ExternalLogins, opt => opt.MapFrom(src =>
                    src.UserLogins != null
                        ? src.UserLogins.Select(l => new ExternalLoginDto
                        {
                            LoginProvider = l.LoginProvider,
                            ProviderDisplayName = l.ProviderDisplayName ?? l.LoginProvider,
                            ProviderKey = l.ProviderKey
                        }).ToList()
                        : null))
                .ReverseMap()
                .ForMember(dest => dest.RtId, x => x.Ignore())
                .ForMember(dest => dest.CkTypeId, x => x.Ignore())
                .ForMember(dest => dest.UserLogins, x => x.Ignore());
        });

        AddIdentity(builder.Services, setupAction);

        return builder;
    }

    private static void AddIdentity(IServiceCollection services, Action<IdentityOptions>? setupAction)
    {
        var builder = services
            .AddIdentity<RtUser, RtRole>(setupAction ?? null!)
            .AddRoleStore<OctoRoleStore>()
            .AddUserStore<OctoUserStore>()
            .AddUserManager<UserManager<RtUser>>()
            .AddRoleManager<RoleManager<RtRole>>()
            .AddDefaultTokenProviders()
            .AddErrorDescriber<OctoErrorDescriber>();

        if (builder.RoleType != null)
        {
            builder.Services.AddScoped(
                typeof(IRoleStore<>).MakeGenericType(builder.RoleType), typeof(OctoRoleStore));
        }

        builder.Services.AddScoped(
            typeof(IUserStore<>).MakeGenericType(builder.UserType), typeof(OctoUserStore));

        // AB#5026: expose the user store's role facet as its own DI service. UserManager casts the
        // IUserStore<TUser> internally and never resolves IUserRoleStore<TUser> from DI, so this is
        // purely additive — it lets protocol-free services (IDelegatedIdentityResolver) read a user's
        // effective roles through the very store that stamps a login token's role claims, without
        // depending on the concrete OctoUserStore or on UserManager. The forwarding lambda keeps the
        // single scoped instance, so both facets share one tenant repository/session.
        builder.Services.AddScoped<IUserRoleStore<RtUser>>(
            sp => (IUserRoleStore<RtUser>)sp.GetRequiredService<IUserStore<RtUser>>());
    }
}