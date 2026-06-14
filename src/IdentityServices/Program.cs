using Duende.IdentityServer.Services;
using IdentityServerPersistence;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.Authentication.Consumers;
using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.Backend.IdentityServices.Configuration;
using Meshmakers.Octo.Backend.IdentityServices.Consumers;
using Meshmakers.Octo.Backend.IdentityServices.Cookies;
using Meshmakers.Octo.Backend.IdentityServices.Resources;
using Meshmakers.Octo.Backend.IdentityServices.Middleware;
using Meshmakers.Octo.Backend.IdentityServices.Routing;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using IQrCodeService = Meshmakers.Octo.Backend.IdentityServices.Services.IQrCodeService;
using QrCodeService = Meshmakers.Octo.Backend.IdentityServices.Services.QrCodeService;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
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
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Logging;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using System.Threading.RateLimiting;
using NLog;
using NLog.Web;
using Persistence.IdentityCkModel.Generated.Blueprints.SystemIdentityBootstrap.v1;
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
    builder.Services.AddSingleton<IQrCodeService, QrCodeService>();
    builder.Services
        .AddSingletonMultipleInterfaces<IdentityConfigurationService, IIdentityConfigurationService,
            ITenantConfigurationService>();

    builder.Services.Configure<OctoIdentityServicesOptions>(options =>
        builder.Configuration.GetSection("Identity").Bind(options));
    builder.Services.Configure<OctoSystemConfiguration>(options =>
        builder.Configuration.GetSection("System").Bind(options));

    // ASP.NET Data Protection: the key ring is persisted in MongoDB (system tenant) — ALWAYS ON,
    // shared by all pods. Identity:DataProtectionKeysPath is no longer a persistence target; if it
    // is set and contains legacy key-*.xml files (old chart still mounts the PVC), they are
    // imported ONCE by DataProtectionKeyStore so existing sessions survive the migration.
    builder.Services.AddSingleton<IXmlRepository, DataProtectionKeyStore>();
    builder.Services.AddOptions<KeyManagementOptions>()
        .Configure<IXmlRepository>((options, repository) => options.XmlRepository = repository);
    builder.Services.AddDataProtection()
        .SetApplicationName("OctoIdentityServices");
    builder.Services.Configure<RouteOptions>(options =>
        options.ConstraintMap.Add("tenantId", typeof(TenantIdRouteConstraint)));

    builder.Services.Configure<CookiePolicyOptions>(options =>
    {
        // This lambda determines whether user consent for non-essential cookies is needed for a given request.
        options.CheckConsentNeeded = _ => true;
        options.MinimumSameSitePolicy = SameSiteMode.None;
    });

    builder.Services.ConfigureOptions<ConfigureDistributionEventHubOptions>();

    builder.Services.AddRateLimiter(options =>
    {
        options.AddPolicy("tenant-discovery", httpContext =>
            RateLimitPartition.GetSlidingWindowLimiter(
                httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                _ => new SlidingWindowRateLimiterOptions
                {
                    PermitLimit = 5,
                    Window = TimeSpan.FromMinutes(1),
                    SegmentsPerWindow = 2,
                    QueueLimit = 0
                }));
        options.OnRejected = async (context, _) =>
        {
            context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            await context.HttpContext.Response.WriteAsync("Too many requests. Please try again later.");
        };
    });

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

    // Service-managed Identity tenant seed (Phase 3 PR #2). Auto-applied on the
    // RefreshTenantStateAsync hook in DefaultConfigurationCreatorService — gated by
    // OctoIdentityServicesOptions.UseBlueprintBootstrap (PR #3). PR #4 cuts SetupTenantAsync
    // over to the blueprint and the flag becomes unconditional; PR #5 removes the flag.
    builder.Services.AddBlueprintSystemIdentityBootstrapV1();

    builder.Services.AddRuntimeEngine()
        .AddOctoIdentityPersistence(configureDistributionEventHub: c =>
        {
            c.AddBroadcastEventConsumer<IdentityProviderUpdateConsumer, IdentityProviderUpdate>();
            c.AddBroadcastEventConsumer<IdentityCorsClientsUpdateConsumer, CorsClientsUpdate>();
            c.AddBroadcastEventConsumer<IdentityTenantManagementConsumer, PreDeleteTenant>();

            c.AddCommandConsumer<CreateIdentityDataCommandRequestConsumer, CreateIdentityDataCommandRequest>(
                QueueNames.CreateIdentityDataCommand);
        });

    // Register Identity-specific CORS policy provider AFTER AddOctoIdentityPersistence,
    // which internally calls AddOctoServiceInfrastructure and registers its own ICorsPolicyProvider.
    // The last registration wins in DI, so this must come after.
    builder.Services.AddSingleton<IdentityCorsPolicyProvider>();
    builder.Services.AddSingleton<ICorsPolicyProvider>(sp => sp.GetRequiredService<IdentityCorsPolicyProvider>());

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
        .AddServerSideSessions<ServerSideSessionStore>()
        .AddCorsPolicyService<CorsPolicyService>()
        .AddAppAuthRedirectUriValidator()
        .AddJwtBearerClientAuthentication();

    // Persist IdentityServer error/failure events to OctoMesh runtime event log
    builder.Services.AddTransient<IEventSink, OctoEventSink>();

    // Scope auth cookies per tenant to prevent cross-tenant session leakage.
    // Identity.Application and idsrv cookies get a .{tenantId} suffix.
    var tenantCookieManager = new TenantCookieManager();
    builder.Services.ConfigureApplicationCookie(o =>
    {
        o.CookieManager = tenantCookieManager;
        o.SlidingExpiration = true;
        // With server-side sessions this bounds BOTH the cookie and the session record.
        // Explicit (was: 14-day framework default) — sliding, so active users stay signed in.
        o.ExpireTimeSpan = TimeSpan.FromDays(7);
    });
    builder.Services.Configure<CookieAuthenticationOptions>("idsrv", o => o.CookieManager = tenantCookieManager);
    builder.Services.Configure<CookieAuthenticationOptions>("idsrv.session", o => o.CookieManager = tenantCookieManager);

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
        .AddJwtBearer(jwt => { jwt.Audience = CommonConstants.OctoApi; });

    builder.Services.AddAuthorization(options =>
    {
        options.AddPolicy(IdentityServiceConstants.IdentityApiReadOnlyPolicy, authorizationPolicyBuilder =>
        {
            authorizationPolicyBuilder.RequireClaim(InfrastructureCommon.ClaimScope,
                CommonConstants.OctoApiFullAccess,
                CommonConstants.OctoApiReadOnly);
        });

        options.AddPolicy(IdentityServiceConstants.IdentityApiReadWritePolicy, authorizationPolicyBuilder =>
        {
            authorizationPolicyBuilder.RequireClaim(InfrastructureCommon.ClaimScope,
                CommonConstants.OctoApiFullAccess);
        });
    });

    builder.Services.AddOctoApiVersioningAndDocumentation(options =>
    {
        options.Scopes = new Dictionary<string, string>
        {
            {
                CommonConstants.OctoApiFullAccess,
                IdentityTexts.Backend_IdentityServices_Api_FullAccess
            },
            {
                CommonConstants.OctoApiReadOnly,
                IdentityTexts.Backend_IdentityServices_Api_ReadOnlyAccess
            }
        };

        options.PolicyScopeMapping = new Dictionary<string, IEnumerable<string>>
        {
            {
                IdentityServiceConstants.IdentityApiReadOnlyPolicy,
                [CommonConstants.OctoApiFullAccess, CommonConstants.OctoApiReadOnly]
            },
            {
                IdentityServiceConstants.IdentityApiReadWritePolicy,
                [CommonConstants.OctoApiFullAccess]
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

    // API Controllers only (no MVC views)
    builder.Services.AddControllers();

    builder.Services.AddAutoMapper(_ =>
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

    // After routing, re-resolve the tenant from the route parameter for v1 API requests.
    // The global TenantMiddleware runs before routing and defaults to the system tenant.
    // This middleware overrides that with the actual tenant from the route, so that scoped
    // services (e.g., OctoUserStore) receive the correct tenant repository.
    app.Use(async (context, next) =>
    {
        var tenantId = context.GetRouteValue(InfrastructureCommon.TenantIdRoute) as string;
        if (!string.IsNullOrWhiteSpace(tenantId))
        {
            var systemContext = context.RequestServices.GetRequiredService<ISystemContext>();
            var tenantRepository = await systemContext.TryFindTenantRepositoryAsync(tenantId);
            if (tenantRepository != null)
            {
                context.Items[InfrastructureCommon.TenantRepositoryName] = tenantRepository;
                context.Items[InfrastructureCommon.TenantIdName] = tenantRepository.TenantId;
            }
        }

        await next();
    });

    var supportedCultures = new[] { "en", "de" };
    var localizationOptions = new RequestLocalizationOptions().SetDefaultCulture(supportedCultures[0])
        .AddSupportedCultures(supportedCultures)
        .AddSupportedUICultures(supportedCultures);

    app.UseRequestLocalization(localizationOptions);

    app.UseRateLimiter();

    // The sequence of the add statements in the configure function is of importance.
    // app.UseAuthentication()
    // !!!UseIdentityServer calls already UseAuthentication; comes before app.UseMvc();
    app.UseOidcTenantResolution();
    app.UseTenantLoginRedirect();
    app.UseIdentityServer();

    app.UseAuthorization();
    app.UseOctoTenantAuthorization();

    // Map API controllers - MUST come before UseEndpoints middleware runs
    app.MapControllers();

    // Redirect root path to the system tenant's login page
    app.MapGet("/", (IOptions<OctoSystemConfiguration> systemConfig) =>
        Results.Redirect($"/{systemConfig.Value.SystemTenantId}/login"));

    // Serve pre-built Angular files from wwwroot for all environments
    app.MapFallbackToFile("index.html");

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