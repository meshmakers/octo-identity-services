using Duende.IdentityServer.Services;
using IdentityServerPersistence;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.Authentication.Consumers;
using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.Backend.IdentityServices.Configuration;
using Meshmakers.Octo.Backend.IdentityServices.Consumers;
using Meshmakers.Octo.Backend.IdentityServices.Resources;
using Meshmakers.Octo.Backend.IdentityServices.Routing;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Extensions;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Commands;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Messages;
using Meshmakers.Octo.Services.Infrastructure;
using Meshmakers.Octo.Services.Infrastructure.Configuration;
using Meshmakers.Octo.Services.Infrastructure.CredentialGenerator;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Meshmakers.Octo.Services.Notifications.Services;
using Meshmakers.Octo.Services.Observability;
using Meshmakers.Octo.Services.Swagger.Configuration;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Logging;
using NLog;
using NLog.Web;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using LogLevel = Microsoft.Extensions.Logging.LogLevel;

// NLog: Setup the logger first to catch all errors
var nLogFactory = LogManager.Setup().RegisterNLogWeb().LoadConfigurationFromFile("nlog.config").LogFactory;
var logger = nLogFactory.GetCurrentClassLogger();

try
{
    logger.Debug("init main");

    var builder = WebApplication.CreateBuilder(new WebApplicationOptions
    {
        Args = args,
        ContentRootPath = Directory.GetCurrentDirectory(),
        WebRootPath = "wwwroot",
    });

    builder.AddObservability()
        .AddSystemContextHealthCheck();

    // NLog: Setup NLog for Dependency injection
    builder.Logging.ClearProviders();
    builder.Logging.SetMinimumLevel(LogLevel.Trace);
    builder.Host.UseNLog();

    // additional providers here needed.
    // allow environment variables to override values from other providers.
    builder.Configuration.AddEnvironmentVariables("OCTO_").AddCommandLine(args)
        .AddUserSecrets(typeof(Program).Assembly, true);


    builder.Services.AddOemServices(builder.Configuration);
    builder.Services.AddOctoNotification();
    builder.Services.AddScoped<IUserEmailInteractionService, UserEmailInteractionService>();
    builder.Services.AddScoped<IUserManagementService, UserManagementService>();
    builder.Services
        .AddSingletonMultipleInterfaces<IdentityConfigurationService, IIdentityConfigurationService,
            ITenantConfigurationService>();

    builder.Services.Configure<OctoIdentityServicesOptions>(options =>
        builder.Configuration.GetSection("Identity").Bind(options));
    builder.Services.Configure<OctoSystemConfiguration>(options =>
        builder.Configuration.GetSection("System").Bind(options));
    builder.Services.Configure<RouteOptions>(options =>
        options.ConstraintMap.Add("tenantId", typeof(TenantIdRouteConstraint)));

    builder.Services.Configure<CookiePolicyOptions>(options =>
    {
        // This lambda determines whether user consent for non-essential cookies is needed for a given request.
        options.CheckConsentNeeded = _ => true;
        options.MinimumSameSitePolicy = SameSiteMode.None;
    });

    builder.Services.ConfigureOptions<ConfigureDistributionEventHubOptions>();

    builder.Services.AddScoped<ICorsPolicyService, CorsPolicyService>();
    builder.Services.AddTransient<ICredentialGenerator, CredentialGenerator>();

    builder.Services.AddDynamicAuthentication()
        .AddGoogle()
        .AddFacebook()
        .AddMicrosoft()
        .AddAzureEntraId()
        .AddOpenLdapAuthentication()
        .AddMicrosoftAdAuthentication();

    builder.Services.AddCors();

    builder.Services.AddRuntimeEngine()
        .AddOctoIdentityPersistence(configureDistributionEventHub: c =>
        {
            c.AddBroadcastEventConsumer<IdentityProviderUpdateConsumer, IdentityProviderUpdate>();

            c.AddCommandConsumer<CreateIdentityDataCommandRequestConsumer, CreateIdentityDataCommandRequest>(
                QueueNames.CreateIdentityDataCommand);
        });

    // Add IdentityServer for authentication using OpenID
    var identityServerBuilder = builder.Services.AddIdentityServer(serverOptions =>
        {
            serverOptions.Events.RaiseErrorEvents = true;
            serverOptions.Events.RaiseInformationEvents = true;
            serverOptions.Events.RaiseFailureEvents = true;
            serverOptions.Events.RaiseSuccessEvents = true;
        })
        .AddClientStore<IOctoClientStore>()
        .AddResourceStore<ResourceStore>()
        .AddPersistedGrantStore<PersistentGrantStore>()
        .AddAspNetIdentity<RtUser>()
        .AddProfileService<UserProfileService>()
        .AddCorsPolicyService<CorsPolicyService>()
        .AddAppAuthRedirectUriValidator()
        .AddJwtBearerClientAuthentication();

    // Service that periodically cleans up tokens in the grant database
    builder.Services.AddSingleton<IHostedService, TokenCleanupHostService>();

    // Add the extra configuration;
    builder.Services.ConfigureOptions<ConfigureIdentityServerOptions>();
    builder.Services.ConfigureOptions<ConfigureOctoOpenApiOptions>();
    builder.Services.ConfigureOptions<ConfigureMapperConfigurationExpression>();

    if (builder.Environment.IsDevelopment())
    {
        identityServerBuilder.AddDeveloperSigningCredential();
    }
    else
    {
        identityServerBuilder.AddOctoSigningCredential();
    }

    builder.Services.TryAddEnumerable(ServiceDescriptor
        .Singleton<IPostConfigureOptions<JwtBearerOptions>, JwtBearerPostConfigureOptions>());
    builder.Services.ConfigureOptions<ConfigureJwtBearerOptions>();

    builder.Services.AddAuthentication()
        .AddJwtBearer(jwt => { jwt.Audience = CommonConstants.IdentityApi; });

    builder.Services.AddAuthorization(options =>
    {
        options.AddPolicy(IdentityServiceConstants.IdentityApiReadOnlyPolicy, authorizationPolicyBuilder =>
        {
            // require IdentityApiFullAccess or IdentityApiReadOnly
            authorizationPolicyBuilder.RequireClaim(InfrastructureCommon.ClaimScope, CommonConstants.IdentityApiFullAccess,
                CommonConstants.IdentityApiReadOnly);
        });

        options.AddPolicy(IdentityServiceConstants.IdentityApiReadWritePolicy, authorizationPolicyBuilder =>
        {
            // require IdentityApiFullAccess
            authorizationPolicyBuilder.RequireClaim(InfrastructureCommon.ClaimScope,
                CommonConstants.IdentityApiFullAccess);
        });
    });

    builder.Services.AddOctoApiVersioningAndDocumentation(options =>
    {
        options.Scopes = new Dictionary<string, string>
        {
            {
                CommonConstants.IdentityApiFullAccess,
                IdentityTexts.Backend_IdentityServices_Api_FullAccess
            },
            {
                CommonConstants.IdentityApiReadOnly,
                IdentityTexts.Backend_IdentityServices_Api_ReadOnlyAccess
            }
        };
        
        options.PolicyScopeMapping = new Dictionary<string, IEnumerable<string>>
        {
            {
                IdentityServiceConstants.IdentityApiReadOnlyPolicy,
                [CommonConstants.IdentityApiFullAccess, CommonConstants.IdentityApiReadOnly]
            },
            {
                IdentityServiceConstants.IdentityApiReadWritePolicy,
                [CommonConstants.IdentityApiFullAccess]
            }
        };
        
        options.XmlDocDataTransferObjectAssemblies =
        [
            typeof(ClientDto).Assembly
        ];

        options.ApiTitle = IdentityTexts.IdentityService_ApiTitle;
        options.ApiDescription = IdentityTexts.IdentityService_ApiDescription;

        options.ClientId = CommonConstants.IdentityServicesSwaggerClientId;
        options.AppName = IdentityTexts.Backend_IdentityServices_UserSchema_Swagger_DisplayName;
    }).AddVersion();

    builder.Services.AddAntiforgery(o => o.SuppressXFrameOptionsHeader = true);

    builder.Services.AddMvc();

    builder.Services.AddAutoMapper(_=>
    {
    }, typeof(Program));
    
    // Migrations are in the IdentityServerPersistence assembly
    builder.Services.AddMigrations(typeof(IdentityServiceConstants).Assembly);
    

    var app = builder.Build();

    app.MapObservability();

    // Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
    {
        app.UseDeveloperExceptionPage();
        IdentityModelEventSource.ShowPII = true;
    }
    else
    {
        app.UseExceptionHandler("/Home/Error");
        // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
        app.UseHsts();
    }

    // Because we are behind an ingress the tls connection is terminated at the ingress itself,
    // the cluster is itself secure, and so we reduce complexity by running http, but the discovery
    // documents should always show https.
    app.Use((context, next) =>
    {
        context.Request.Scheme = "https";
        return next();
    });

    app.UseCors();

    // Conversion of request query jwt token to cookie for switch from dashboard to hangfire ui dashboard
    app.UseOctoTenants();
    app.UseOctoCookieBasedAuthentication();

    app.UseHttpsRedirection();
    app.UseStaticFiles();
    app.UseCookiePolicy();

    app.UseOctoApiVersioningAndDocumentation();

    app.UseRouting();

    var supportedCultures = new[] { "en", "de" };
    var localizationOptions = new RequestLocalizationOptions().SetDefaultCulture(supportedCultures[0])
        .AddSupportedCultures(supportedCultures)
        .AddSupportedUICultures(supportedCultures);

    app.UseRequestLocalization(localizationOptions);

    // The sequence of the add statements in the configure function is of importance.
    // app.UseAuthentication()
    // !!!UseIdentityServer calls already UseAuthentication; comes before app.UseMvc();
    app.UseIdentityServer();

    app.UseAuthorization();

    app.MapDefaultControllerRoute();
    app.MapControllerRoute("default", "{tenantId:tenantId=System}/{controller=Home}/{action=Index}/{id?}");
    
    // Initialisierung abfangen
    app.Lifetime.ApplicationStarted.Register(() =>
    {
        var eventRepository = app.Services.GetRequiredService<IEventRepository>();
        eventRepository.StoreSystemInformationEvent(RtEventSourcesEnum.IdentityService,
            "Identity Services started.");
    });

    app.Run();
}
catch (Exception ex)
{
    //NLog: catch setup errors
    logger.Error(ex, "Stopped program because of exception");
    throw;
}
finally
{
    // Ensure to flush and stop internal timers/threads before application-exit (Avoid segmentation fault on Linux)
    LogManager.Shutdown();
}