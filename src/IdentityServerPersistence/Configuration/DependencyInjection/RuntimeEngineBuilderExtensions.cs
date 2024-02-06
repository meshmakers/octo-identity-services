using Duende.IdentityServer.Models;
using IdentityServerPersistence.AutoMap;
using IdentityServerPersistence.Configuration.DependencyInjection;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Common.DistributionEventHub.Configuration;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Runtime.Engine.Configuration.DependencyInjection;
using Meshmakers.Octo.Services.Common.Cors;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.ConstructionKit.Generated.System.Identity.v1;

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

        // Add the construction kits as embedded repository
        builder.Services.AddCkModelSystemIdentity();

        // Add services of Identity module
        builder.Services.AddTransient<IDefaultConfigurationCreatorService, DefaultConfigurationCreatorService>();

        builder.Services.AddScoped<IOctoClientStore, ClientStore>();
        builder.Services.AddScoped<IOctoResourceStore, ResourceStore>();
        builder.Services.AddScoped<IOctoPersistentGrantStore, PersistentGrantStore>();
        builder.Services.AddScoped<IOctoIdentityProviderStore, IdentityProviderStore>();

        builder.Services.AddSingleton<CorsPolicyProvider>();
        builder.Services.AddSingleton<ICorsPolicyProvider>(provider => provider.GetRequiredService<CorsPolicyProvider>());

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