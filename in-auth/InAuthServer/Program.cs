using Serilog.Events;
using Serilog;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Quartz;
using System.Security.Cryptography.X509Certificates;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Microsoft.AspNetCore.HttpOverrides;
using InAuthServer;
using OpenIddict.Validation.AspNetCore;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using OpenTelemetry.Exporter;


Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .CreateBootstrapLogger();

Log.Information("Starting up");

try
{
    var builder = WebApplication.CreateBuilder(args);

    // Add services to the container.
    builder.Services.AddControllersWithViews();

    builder.Services.AddSerilog((services, lc) => lc
    .ReadFrom.Configuration(builder.Configuration)
    .ReadFrom.Services(services)
    .Enrich.FromLogContext()
    .WriteTo.Console());

    builder.Services.Configure<CookiePolicyOptions>(options =>
    {
        options.CheckConsentNeeded = context => true;
        options.MinimumSameSitePolicy = SameSiteMode.None;
    });
    builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
        {
            options.LoginPath = "/account/login";
        });
    builder.Services.AddAuthorization();

    builder.Services.AddQuartz(options =>
    {
        options.UseSimpleTypeLoader();
        options.UseInMemoryStore();
    });
    // Register the Quartz.NET service and configure it to block shutdown until jobs are complete.
    builder.Services.AddQuartzHostedService(options => options.WaitForJobsToComplete = true);

    builder.Services.AddDbContext<DbContext>(options =>
    {
        // Configure the context to use an in-memory store.
        options.UseInMemoryDatabase(nameof(DbContext));
        //options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
        // Register the entity sets needed by OpenIddict.
        options.UseOpenIddict();
    });
    builder.Services.AddOpenIddict()
    // Register the OpenIddict core components.
    .AddCore(options =>
    {
        // Configure OpenIddict to use the EF Core stores/models.
        options.UseEntityFrameworkCore()
            .UseDbContext<DbContext>();
        options.UseQuartz();
    })
    // Register the OpenIddict server components.
    .AddServer(options =>
    {
        options
            .SetAuthorizationEndpointUris("connect/authorize")
            .SetLogoutEndpointUris("connect/logout")
            .SetTokenEndpointUris("connect/token")
            .SetUserinfoEndpointUris("connect/userinfo")
            .SetIntrospectionEndpointUris("connect/introspect")
            .SetVerificationEndpointUris("connect/verify");
        //options.UseDataProtection();
        options
            .AllowClientCredentialsFlow()
            .AllowAuthorizationCodeFlow()
            //.RequireProofKeyForCodeExchange()
            .AllowRefreshTokenFlow();

        //options.DisableAccessTokenEncryption();
        options
            .AddEphemeralEncryptionKey()
            .AddEphemeralSigningKey()
            .DisableAccessTokenEncryption();

        options.AddDevelopmentEncryptionCertificate()
        .AddDevelopmentSigningCertificate();

        // if (builder.Environment.IsDevelopment())
        // {
        //     //臨時金鑰
        //     //options
        //     //.AddEphemeralEncryptionKey()
        //     //.AddEphemeralSigningKey();
        //     //開發證書
        //     options
        //         .AddEphemeralEncryptionKey()
        //         .AddEphemeralSigningKey()
        //         .DisableAccessTokenEncryption();

        //     options.AddDevelopmentEncryptionCertificate()
        //     .AddDevelopmentSigningCertificate();
        // }
        // else
        // {
        //     string encryptionPath = Path.Combine(builder.Environment.ContentRootPath, "Certs/encryption-certificate.pfx");
        //     // Log.Information($"encryptionPath:{encryptionPath}");
        //     var encryption = new X509Certificate2(File.ReadAllBytes(encryptionPath));
        //     options.AddEncryptionCertificate(encryption);
        //     string signingPath = Path.Combine(builder.Environment.ContentRootPath, "Certs/signing-certificate.pfx");
        //     // Log.Information($"encryptionPath:{signingPath}");
        //     var signing = new X509Certificate2(File.ReadAllBytes(signingPath));
        //     options.AddSigningCertificate(signing);
        // }

        // Mark the "email", "profile" and "roles" scopes as supported scopes.
        options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles);
        // Register scopes (permissions)
        options.RegisterScopes("scope1", "scope2");

        // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
        options
            .UseAspNetCore()
            .EnableStatusCodePagesIntegration()
            .EnableAuthorizationEndpointPassthrough()
            .EnableLogoutEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            .EnableUserinfoEndpointPassthrough()
            .EnableVerificationEndpointPassthrough()
            .DisableTransportSecurityRequirement();
    })    // Register the OpenIddict validation components.
    .AddValidation(options =>
    {
        //options.UseDataProtection();
        // Import the configuration from the local OpenIddict server instance.
        options.UseLocalServer();
        // Register the ASP.NET Core host.
        options.UseAspNetCore();
        options.EnableAuthorizationEntryValidation();
    });

    builder.Services.Configure<ForwardedHeadersOptions>(options =>
    {
        options.ForwardedHeaders = ForwardedHeaders.XForwardedProto;
    });

    builder.Services.AddHostedService<TestData>();
    var otlpEndpoint = builder.Configuration["OTLP_ENDPOINT_URL"];
    Log.Information($"TracingOtlpEndpoint:{otlpEndpoint}");
    var otel = builder.Services.AddOpenTelemetry();
    // Configure OpenTelemetry Resources with the application name
    otel.ConfigureResource(resource => resource
        .AddService(serviceName: builder.Environment.ApplicationName));

    // Add Metrics for ASP.NET Core and our custom metrics and export to Prometheus
    otel.WithMetrics(metrics => metrics
        // Metrics provider from OpenTelemetry
        .AddAspNetCoreInstrumentation()
        .AddRuntimeInstrumentation()
        .AddMeter("ExAuthServer")
        // Metrics provides by ASP.NET Core in .NET 8
        .AddMeter("Microsoft.AspNetCore.Hosting")
        .AddMeter("Microsoft.AspNetCore.Server.Kestrel")
        .AddOtlpExporter(otlpOptions =>
        {
            otlpOptions.Protocol = OtlpExportProtocol.Grpc;
            otlpOptions.Endpoint = new Uri(otlpEndpoint!);
        })
        .AddPrometheusExporter());

    // Add Tracing for ASP.NET Core and our custom ActivitySource and export to Jaeger
    otel.WithTracing(tracing =>
    {
        tracing.AddAspNetCoreInstrumentation();
        tracing.AddHttpClientInstrumentation();
        tracing.AddSqlClientInstrumentation();
        tracing.AddSource("ExAuthServer");
        if (otlpEndpoint != null)
        {
            tracing.AddOtlpExporter(otlpOptions =>
            {
                otlpOptions.Protocol = OtlpExportProtocol.Grpc;
                otlpOptions.Endpoint = new Uri(otlpEndpoint);
            });
        }
        else
        {
            tracing.AddConsoleExporter();
        }
    });

    var app = builder.Build();

    if (app.Environment.IsProduction())
    {
        var fordwardedHeaderOptions = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
        };
        fordwardedHeaderOptions.KnownNetworks.Clear();
        fordwardedHeaderOptions.KnownProxies.Clear();
        app.UseForwardedHeaders(fordwardedHeaderOptions);
        app.UseExceptionHandler("/Home/Error");
        // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
        app.UseHsts();

        app.Use((context, next) =>
        {
            context.Request.Scheme = "https";
            return next(context);
        });

        app.UseHttpsRedirection();
    }

    app.UseCors(x => x
    .AllowAnyMethod()
    .AllowAnyHeader()
    .SetIsOriginAllowed(_ => true) // allow any origin
    .AllowCredentials());

    app.UseStaticFiles();

    app.UseRouting();

    app.UseAuthentication();

    app.UseAuthorization();

    app.MapControllerRoute(
        name: "default",
        pattern: "{controller=Home}/{action=Index}/{id?}");

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Unhandled exception");
}
finally
{
    Log.Error("Shut down complete");
    Log.CloseAndFlush();
}
