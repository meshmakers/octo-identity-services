#pragma warning disable 1591
using IdentityServerPersistence.Configuration;
using Meshmakers.Octo.Backend.PolicyServices.Configuration;
using Meshmakers.Octo.Backend.PolicyServices.Services;
using Meshmakers.Octo.Common.Shared;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Services.Common;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.Extensions.Options;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace Meshmakers.Octo.Backend.PolicyServices;

public class Startup
{
    public Startup(IConfiguration configuration)
    {
        Configuration = configuration;
    }

    public IConfiguration Configuration { get; }

    // This method gets called by the runtime. Use this method to add services to the container.
    public void ConfigureServices(IServiceCollection services)
    {
        services.Configure<OctoPolicyOptions>(options => Configuration.GetSection("Policy").Bind(options));
        services.Configure<OctoSystemConfiguration>(options => Configuration.GetSection("System").Bind(options));


        services.ConfigureOptions<ConfigureDistributionEventHubOptions>();
        services.ConfigureOptions<ConfigureJwtBearerOptions>();

        services.AddTransient<IUserSchemaService, UserSchemaService>();

        services.AddOctoServiceInfrastructure("PolicyService");

        services.AddRuntimeEngine()
            .AddMongoDbRuntimeRepository();

        services.AddAuthentication()
            .AddJwtBearer(jwt => { jwt.Audience = CommonConstants.PolicyApi; });

        services.AddAuthorization(options =>
        {
            options.AddPolicy(PolicyServiceConstants.PolicyApiReadOnlyPolicy, authorizationPolicyBuilder =>
            {
                // require SystemApiFullAccess or SystemApiReadOnly
                authorizationPolicyBuilder.RequireClaim(BackendCommon.ClaimScope, CommonConstants.PolicyApiFullAccess,
                    CommonConstants.PolicyApiReadOnly);
            });

            options.AddPolicy(PolicyServiceConstants.PolicyApiReadWritePolicy, authorizationPolicyBuilder =>
            {
                // require SystemApiFullAccess
                authorizationPolicyBuilder.RequireClaim(BackendCommon.ClaimScope, CommonConstants.PolicyApiFullAccess);
            });
        });

        services.AddApiVersioning(options => options.ReportApiVersions = true);
        services.AddVersionedApiExplorer();

        //  services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_3_0);
        services.AddControllers();

        services.AddTransient<IConfigureOptions<SwaggerGenOptions>, ConfigureSwaggerOptions>();
        services.AddSwaggerGen();
    }

    // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    public void Configure(IApplicationBuilder app, IHost host, IWebHostEnvironment env, ISystemContext systemContext,
        IApiVersionDescriptionProvider apiVersionDescriptionProvider, IUserSchemaService userSchemaService)
    {
        if (env.IsDevelopment()) app.UseDeveloperExceptionPage();

        app.UseCors();
        app.UseHttpsRedirection();

        app.UseRouting();

        app.UseAuthorization();

        app.UseEndpoints(endpoints => { endpoints.MapControllers(); });
    }
}