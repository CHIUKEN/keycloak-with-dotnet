using Azure.Core;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Security.Claims;
using Microsoft.AspNetCore;
using System.Net;

namespace InAuthServer.Controllers;

public class AuthorizationController : Controller
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _authorizationScopeManager;

    public AuthorizationController(IOpenIddictApplicationManager applicationManager, IOpenIddictAuthorizationManager authorizationManager, IOpenIddictScopeManager authorizationScopeManager)
    {
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _authorizationScopeManager = authorizationScopeManager;
    }


    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
                          throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // Retrieve the user principal stored in the authentication cookie.
        var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        // If the user principal can't be extracted, redirect the user to the login page.
        if (!result.Succeeded)
        {
            return Challenge(
                authenticationSchemes: CookieAuthenticationDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                        Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
                });
        }

        // Create a new claims principal
        var claims = new List<Claim>
            {
                // 'subject' claim which is required
                new Claim(Claims.Subject, result.Principal!.Identity!.Name!),
                new Claim("some claim", "some value").SetDestinations(Destinations.AccessToken),
                new Claim(Claims.Email, "some@email").SetDestinations(Destinations.IdentityToken)
            };

        var claimsIdentity = new ClaimsIdentity(claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

        // Set requested scopes (this is not done automatically)
        claimsPrincipal.SetScopes(request.GetScopes());
        // Set resource
        var resources = await _authorizationScopeManager.ListResourcesAsync(request.GetScopes()).ToListAsync();
        claimsPrincipal.SetResources(resources);

        //claimsPrincipal.SetAuthorizationId(await _authorizationScopeManager.ListResourcesAsync(request.GetScopes()).ToListAsync());

        foreach (var claim in claimsPrincipal.Claims)
        {
            claim.SetDestinations(GetDestinations(claim, claimsPrincipal));
        }
        // Signing in with the OpenIddict authentiction scheme trigger OpenIddict to issue a code (which can be exchanged for an access token)
        return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

    }

    [HttpGet("~/connect/logout")]
    public IActionResult Logout() => View();

    [ActionName(nameof(Logout)), HttpPost("~/connect/logout"), ValidateAntiForgeryToken]
    public async Task<IActionResult> LogoutPost()
    {
        // Ask ASP.NET Core Identity to delete the local and external cookies created
        // when the user agent is redirected from the external identity provider
        // after a successful authentication flow (e.g Google or Facebook).
        //await _signInManager.SignOutAsync();
        await HttpContext.SignOutAsync();
        // Returning a SignOutResult will ask OpenIddict to redirect the user agent
        // to the post_logout_redirect_uri specified by the client application or to
        // the RedirectUri specified in the authentication properties if none was set.
        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties
            {
                RedirectUri = "/"
            });
    }

    [HttpPost("~/connect/token")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        ClaimsPrincipal claimsPrincipal;

        if (request.IsClientCredentialsGrantType())
        {
            var application = await _applicationManager.FindByClientIdAsync(request!.ClientId!);
            if (application == null)
            {
                throw new InvalidOperationException("The application details cannot be found in the database.");
            }
            // Note: the client credentials are automatically validated by OpenIddict:
            // if client_id or client_secret are invalid, this action won't be invoked.
            // Create the claims-based identity that will be used by OpenIddict to generate tokens.
            var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                nameType: Claims.Name,
                roleType: Claims.Role);

            // Subject (sub) is a required field, we use the client id as the subject identifier here.
            // Use the client_id as the subject identifier.
            identity.SetClaim(Claims.Subject, await _applicationManager.GetClientIdAsync(application) ?? "");
            identity.SetClaim(Claims.Name, await _applicationManager.GetDisplayNameAsync(application) ?? "");
            // Add some claim, don't forget to add destination otherwise it won't be added to the access token.
            //identity.AddClaim("some-claim", "some-value", OpenIddictConstants.Destinations.AccessToken);
            foreach (var scope in request.GetScopes())
            {
                identity.AddClaim(Claims.Private.Scope, scope);
            }

            claimsPrincipal = new ClaimsPrincipal(identity);
            // set scopes
            claimsPrincipal.SetScopes(request.GetScopes());
            // set resources
            var resources = await _authorizationScopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync();
            claimsPrincipal.SetResources(resources);

            foreach (var claim in claimsPrincipal.Claims)
            {
                claim.SetDestinations(GetDestinations(claim, claimsPrincipal));
            }
        }
        else if (request.IsAuthorizationCodeGrantType())
        {
            // Retrieve the claims principal stored in the authorization code
            claimsPrincipal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme))!.Principal!;
        }

        else if (request.IsRefreshTokenGrantType())
        {
            // Retrieve the claims principal stored in the refresh token.
            claimsPrincipal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme))!.Principal!;
        }

        else
        {
            throw new InvalidOperationException("The specified grant type is not supported.");
        }

        // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
        return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("~/connect/userinfo")]
    public async Task<IActionResult> Userinfo()
    {
        var claimsPrincipal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;

        //return Ok(new
        //{
        //    Name = claimsPrincipal.GetClaim(OpenIddictConstants.Claims.Subject),
        //    Occupation = "Developer",
        //    Age = 43
        //});
        var random = new Random();
        var randomEmailVerified = (random.Next(50) & 2) == 0;
        //var userId = GetUserId(claimsPrincipal!.GetClaim(Claims.Subject)!);
        var userId = claimsPrincipal!.GetClaim(OpenIddictConstants.Claims.Subject)!;
        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            // Note: the "sub" claim is a mandatory claim and must be included in the JSON response.
            [Claims.Subject] = userId,
            [Claims.Email] = $"{userId}@example.com",
            [Claims.EmailVerified] = randomEmailVerified,
            [Claims.Username] = claimsPrincipal!.GetClaim(Claims.Username)! ?? $"UserName-{userId}",
            [Claims.Name] = claimsPrincipal!.GetClaim(Claims.Name) ?? $"Name-{userId}",
            [Claims.GivenName] = $"GivenName-{userId}",
            [Claims.FamilyName] = $"FamilyName-{userId}",
            ["dept-claim"] = "dept_test",
        };
        return Ok(claims);
        //if (User.HasScope(Scopes.Email))
        //{
        //    claims[Claims.Email] = await _userManager.GetEmailAsync(user);
        //    claims[Claims.EmailVerified] = await _userManager.IsEmailConfirmedAsync(user);
        //}

        //if (User.HasScope(Scopes.Phone))
        //{
        //    claims[Claims.PhoneNumber] = await _userManager.GetPhoneNumberAsync(user);
        //    claims[Claims.PhoneNumberVerified] = await _userManager.IsPhoneNumberConfirmedAsync(user);
        //}

        //if (User.HasScope(Scopes.Roles))
        //{
        //    claims[Claims.Role] = await _userManager.GetRolesAsync(user);
        //}

        // Note: the complete list of standard claims supported by the OpenID Connect specification
        // can be found here: http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims

        //return Ok(claims);
    }

    private IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
    {
        // Note: by default, claims are NOT automatically included in the access and identity tokens.
        // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
        // whether they should be included in access tokens, in identity tokens or in both.

        switch (claim.Type)
        {
            case Claims.Name:
                yield return Destinations.AccessToken;

                if (principal.HasScope(Scopes.Profile))
                    yield return Destinations.IdentityToken;

                yield break;

            case Claims.Email:
                yield return Destinations.AccessToken;

                if (principal.HasScope(Scopes.Email))
                    yield return Destinations.IdentityToken;

                yield break;

            case Claims.Role:
                yield return Destinations.AccessToken;

                if (principal.HasScope(Scopes.Roles))
                    yield return Destinations.IdentityToken;

                yield break;

            // Never include the security stamp in the access and identity tokens, as it's a secret value.
            case "AspNet.Identity.SecurityStamp":
                yield break;

            default:
                yield return Destinations.AccessToken;
                yield break;
        }
    }

    private static int GetUserId(string name)
    {
        if (!int.TryParse(name, out int numInt))
        {
            char sp = name.Split().FirstOrDefault()?.ToCharArray().FirstOrDefault() ?? 'a';
            int number = sp - '0';
            return number;

        }
        return numInt;

    }
}
