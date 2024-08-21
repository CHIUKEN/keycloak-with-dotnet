using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using System.Globalization;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace InAuthServer;

public class TestData : IHostedService
{
    private readonly IServiceProvider _serviceProvider;

    public TestData(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using var scope = _serviceProvider.CreateScope();

        var context = scope.ServiceProvider.GetRequiredService<DbContext>();
        await context.Database.EnsureCreatedAsync(cancellationToken);

        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        // Postman - ClientCredentials
        if (await manager.FindByClientIdAsync("postman", cancellationToken) is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "postman",
                ClientSecret = "postman-123!",
                DisplayName = "Postman(Scope1)",
                RedirectUris = { new Uri("https://oauth.pstmn.io/v1/callback") },
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,

                    OpenIddictConstants.Permissions.Prefixes.Scope + "scope1"
                }
            }, cancellationToken);
        }
        // Postman - ClientCredentials
        if (await manager.FindByClientIdAsync("postman1", cancellationToken) is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "postman1",
                ClientSecret = "postman-123!",
                DisplayName = "Postman(Scope2)",
                RedirectUris = { new Uri("https://oauth.pstmn.io/v1/callback") },
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,

                    OpenIddictConstants.Permissions.Prefixes.Scope + "scope2"
                }
            }, cancellationToken);
        }

        // Swagger - AuthorizationCode
        if (await manager.FindByClientIdAsync("swagger", cancellationToken) is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "swagger",
                ClientSecret = "swagger-123!",
                DisplayName = "Swagger(PKCE)",
                ApplicationType = ApplicationTypes.Web,
                ClientType = ClientTypes.Confidential,
                RedirectUris = {
                    new Uri("https://localhost:7138/swagger/oauth2-redirect.html"),
                    new Uri("https://localhost:7225/signin-oidc")
                },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Logout,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,

                    Permissions.Prefixes.Scope + "scope1",
                    Permissions.Prefixes.Scope + "scope2",
                },
                Settings =
                {
                    [Settings.TokenLifetimes.AccessToken] = TimeSpan.FromMinutes(10).ToString("c", CultureInfo.InvariantCulture)
                }
            }, cancellationToken);
        }


        var client1 = await manager.FindByClientIdAsync("oidc-debugger", cancellationToken);
        if (client1 != null)
        {
            await manager.DeleteAsync(client1, cancellationToken);
        }
        if (await manager.FindByClientIdAsync("oidc-debugger", cancellationToken) is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "oidc-debugger",
                ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654",
                ConsentType = ConsentTypes.Explicit,
                DisplayName = "Postman client application",
                RedirectUris =
                {
                    new Uri("https://oidcdebugger.com/debug"),
                    new Uri("https://oauth.pstmn.io/v1/callback"),
                    new Uri("https://localhost:7151/signin-oidc"),
                    new Uri("https://backend.codinglife.idv.tw/signin-oidc")
                },
                PostLogoutRedirectUris =
                {
                    new Uri("https://oauth.pstmn.io/v1/callback"),
                    new Uri("https://backend.codinglife.idv.tw/signout-oidc")
                },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Logout,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles
                },
                //Requirements =
                //{
                //    Requirements.Features.ProofKeyForCodeExchange
                //}
            }, cancellationToken);
        }
        var client = await manager.FindByClientIdAsync("keycloak", cancellationToken);
        if (client != null)
        {
            await manager.DeleteAsync(client, cancellationToken);
        }
        if (await manager.FindByClientIdAsync("keycloak", cancellationToken) is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "keycloak",
                ClientSecret = "keycloak-123!",
                ConsentType = ConsentTypes.Explicit,
                DisplayName = "Keycloak client application",
                RedirectUris =
                {
                    new Uri("http://localhost:8080/realms/master/broker/in-oidc/endpoint"),
                    new Uri("https://in-keycloak.codinglife.idv.tw/realms/master/broker/in-oidc/endpoint"),
                    new Uri("https://oauth.pstmn.io/v1/callback"),
                    new Uri("http://localhost:8080/realms/Test/broker/oidc/endpoint"),
                    new Uri("http://localhost:8080/realms/demo/broker/oidc/endpoint")
                },
                PostLogoutRedirectUris =
                {
                    new Uri("https://auth.codinglife.idv.tw/account/logout"),
                    new Uri("https://in-keycloak.codinglife.idv.tw/realms/master/broker/in-oidc/endpoint/logout_response")
                },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Logout,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles
                },
                //Requirements =
                //{
                //    Requirements.Features.ProofKeyForCodeExchange
                //}
            }, cancellationToken);
        }
        //"https://auth.codinglife.idv.tw/realms/master/broker/in-oidc/endpoint"
        //http://localhost:8080/realms/master/broker/in-oidc/endpoint

        //introspection client
        if (await manager.FindByClientIdAsync("resource_server_1", cancellationToken) == null)
        {
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = "resource_server_1",
                ClientSecret = "846B62D0-DEF9-4215-A99D-86E6B8DAB342",
                DisplayName = "Resource Server Introspection",
                Permissions =
                    {
                        Permissions.Endpoints.Introspection
                    }
            };

            await manager.CreateAsync(descriptor, cancellationToken);
        }
        //introspection client
        if (await manager.FindByClientIdAsync("resource_server_2", cancellationToken) == null)
        {
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = "resource_server_2",
                ClientSecret = "846B62D0-DEF9-4215-A99D-86E6B8DAB349",
                DisplayName = "Resource Server Introspection",
                Permissions =
                    {
                        Permissions.Endpoints.Introspection
                    }
            };

            await manager.CreateAsync(descriptor, cancellationToken);
        }

        await CreateScopesAsync(scope);
    }
    private static async Task CreateScopesAsync(IServiceScope scope)
    {
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

        if (await manager.FindByNameAsync("scope1") is null)
        {
            await manager.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = "scope1",
                Resources =
                {
                    "resource_server_1","resource_server_2"
                }
            });
        }

        if (await manager.FindByNameAsync("scope2") is null)
        {
            await manager.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = "scope2",
                Resources =
                {
                    "resource_server_1",
                }
            });
        }
    }
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
