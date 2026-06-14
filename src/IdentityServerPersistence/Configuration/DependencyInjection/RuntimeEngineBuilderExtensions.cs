using Duende.IdentityServer.Models;
using IdentityServerPersistence.AutoMap;
using IdentityServerPersistence.Configuration.DependencyInjection;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.Services.Login;
using IdentityServerPersistence.SystemStores;
using Microsoft.AspNetCore.Identity;
using Meshmakers.Octo.Common.DistributionEventHub.Configuration;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Runtime.Contracts.Blueprints;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Runtime.Engine.Configuration.DependencyInjection;
using Meshmakers.Octo.Services.Infrastructure;
using Meshmakers.Octo.Services.Infrastructure.Services;
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
        builder.Services.AddScoped<IGroupRoleResolver, GroupRoleResolver>();
        builder.Services.AddScoped<ICrossTenantAuthenticationService, CrossTenantAuthenticationService>();
        builder.Services.AddScoped<ICrossTenantUserProvisioningService, CrossTenantUserProvisioningService>();
        builder.Services.AddScoped<IAllowedTenantsResolver, AllowedTenantsResolver>();
        builder.Services.AddScoped<IEmailDomainGroupRuleStore, EmailDomainGroupRuleStore>();
        builder.Services.AddScoped<ILoginGroupAssignmentService, LoginGroupAssignmentService>();
        builder.Services.AddScoped<ITenantDiscoveryService, TenantDiscoveryService>();
        builder.Services.AddScoped<IClientMirrorProvisioningService, ClientMirrorProvisioningService>();

        builder.Services.AddSingleton<AttributeStringValueListConverter>();
        builder.Services.AddAutoMapper(cfg =>
        {
            cfg.CreateMap<ICollection<string>, IAttributeValueList<string>>()
                .ConvertUsing<AttributeStringValueListConverter>();

            cfg.CreateMap<RtClient, Client>();
            cfg.CreateMap<RtPersistedGrant, PersistedGrant>()
                .ForMember(dest => dest.Type, opt => opt.MapFrom(src => src.GrantType))
                .ForMember(dest => dest.Key, opt => opt.MapFrom(src => src.GrantKey))
                .ForMember(dest => dest.CreationTime, opt => opt.MapFrom(src => src.CreationDateTime))
                .ForMember(dest => dest.Expiration, opt => opt.MapFrom(src => src.ExpirationDateTime));
            cfg.CreateMap<RtIdentityResource, IdentityResource>()
                .ForMember(dest => dest.Emphasize, opt => opt.MapFrom(src => src.IsEmphasized))
                .ForMember(dest => dest.Required, opt => opt.MapFrom(src => src.IsRequired))
                .ForMember(dest => dest.UserClaims, opt => opt.MapFrom(src => src.Claims));
            cfg.CreateMap<IdentityResource, RtIdentityResource>()
                .ForMember(dest => dest.IsEmphasized, opt => opt.MapFrom(src => src.Emphasize))
                .ForMember(dest => dest.IsRequired, opt => opt.MapFrom(src => src.Required))
                .ForMember(dest => dest.Claims, opt => opt.MapFrom(src => src.UserClaims));

            cfg.CreateMap<RtSecretRecord, Secret>();
            cfg.CreateMap<PersistedGrant, RtPersistedGrant>()
                .ForMember(dest => dest.GrantKey, opt => opt.MapFrom(src => src.Key))
                .ForMember(dest => dest.GrantType, opt => opt.MapFrom(src => src.Type))
                .ForMember(dest => dest.ConsumedDateTime, opt => opt.MapFrom(src => src.ConsumedTime))
                .ForMember(dest => dest.CreationDateTime, opt => opt.MapFrom(src => src.CreationTime))
                .ForMember(dest => dest.ExpirationDateTime, opt => opt.MapFrom(src => src.Expiration));

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

            cfg.CreateMap<RtApiResource, ApiResource>()
                .ForMember(dest => dest.UserClaims, opt => opt.MapFrom(src => src.Claims));

            cfg.CreateMap<ApiResource, RtApiResource>()
                .ForMember(dest => dest.Claims, opt => opt.MapFrom(src => src.UserClaims));

            cfg.CreateMap<RtApiScope, ApiScope>()
                .ForMember(dest => dest.Emphasize, opt => opt.MapFrom(src => src.IsEmphasized))
                .ForMember(dest => dest.Required, opt => opt.MapFrom(src => src.IsRequired))
                .ForMember(dest => dest.UserClaims, opt => opt.MapFrom(src => src.Claims));
            cfg.CreateMap<ApiScope, RtApiScope>()
                .ForMember(dest => dest.IsEmphasized, opt => opt.MapFrom(src => src.Emphasize))
                .ForMember(dest => dest.IsRequired, opt => opt.MapFrom(src => src.Required))
                .ForMember(dest => dest.Claims, opt => opt.MapFrom(src => src.UserClaims));

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
    }
}