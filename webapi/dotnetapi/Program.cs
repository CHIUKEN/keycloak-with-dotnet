using Keycloak.AuthServices.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Logging;
using Microsoft.OpenApi.Models;
using Serilog;
using Serilog.Events;
using Swashbuckle.AspNetCore.SwaggerUI;

var builder = WebApplication.CreateBuilder(args);

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    IdentityModelEventSource.ShowPII = true;
    builder.Services.AddSerilog((services, lc) => lc
    .ReadFrom.Configuration(builder.Configuration)
    .ReadFrom.Services(services)
    .Enrich.FromLogContext()
    .WriteTo.Console());

    builder.Services.AddEndpointsApiExplorer();

    builder.Services
            .AddAuthorization()
            .AddKeycloakWebApiAuthentication(builder.Configuration, o =>
            {
                o.RequireHttpsMetadata = false;
            });

    builder.Services.AddSwaggerGen(c =>{
        c.AddSecurityDefinition(
                "oauth2",
                new OpenApiSecurityScheme
                {
                    Type = SecuritySchemeType.OAuth2,
                    Flows = new OpenApiOAuthFlows
                    {
                        AuthorizationCode = new OpenApiOAuthFlow
                        {
                            AuthorizationUrl = new Uri("http://localhost:8080/realms/Test/protocol/openid-connect/auth"),
                            TokenUrl = new Uri("http://localhost:8080/realms/Test/protocol/openid-connect/token"),
                            Scopes = new Dictionary<string, string> {

                            }
                        }
                    }
                });

        c.AddSecurityRequirement(
            new OpenApiSecurityRequirement
            {
                    {
                        new OpenApiSecurityScheme{
                            Reference = new OpenApiReference{
                                Id = "oauth2", //The name of the previously defined security scheme.
                                Type = ReferenceType.SecurityScheme
                            }
                        },
                        new List<string>()
                    }
            });
    });

    var app = builder.Build();

    // Configure the HTTP request pipeline.
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Versioned API v1.0");
        c.DocumentTitle = "Title Documentation";
        c.DocExpansion(DocExpansion.None);
        c.OAuthClientId("api");
        c.OAuthClientSecret("JuHtuQLxyO1DUT1QyL1ifBpEzLY373NQ");
        c.OAuthAppName("Test API");
        c.OAuthUsePkce();
    });

    //app.UseHttpsRedirection();

    var summaries = new[]
    {
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };
    app.MapGet("/weatherforecast", () =>
    {
        var forecast = Enumerable.Range(1, 5).Select(index =>
            new WeatherForecast
            (
                DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                Random.Shared.Next(-20, 55),
                summaries[Random.Shared.Next(summaries.Length)]
            ))
            .ToArray();
        return forecast;
    })
    .WithName("GetWeatherForecast")
    .WithOpenApi()
    .RequireAuthorization();

    app.UseAuthentication();
    app.UseAuthorization();

    app.Run();
}
catch (Exception ex)
{
    // 紀錄你的應用程式中未被捕捉的例外 (Unhandled Exception)
    Log.Error(ex, "Something went wrong");
}
finally
{
    // 將最後剩餘的 Log 寫入到 Sinks 去！
    Log.CloseAndFlush();
}
record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
