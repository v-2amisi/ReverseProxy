using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System.Threading.Tasks;
using CustomReverseProxy.Models;
using System;
using System.Web;

namespace CustomReverseProxy.Middlewares
{
    public class AuthenticationMiddleware
    {
        private readonly RequestDelegate _next;
	    private readonly AppSettings _appSettings;

        public AuthenticationMiddleware(RequestDelegate next, IOptions<AppSettings> appSettings)
        {
            _next = next;
	        _appSettings = appSettings.Value;
        }

        public async Task Invoke(HttpContext context)
        {
            var loginRequestPath = context.Request.Path;
            string returnUrl = context.Request.QueryString.Value;
            if (string.IsNullOrEmpty(returnUrl)) returnUrl = "/";
            if (loginRequestPath.StartsWithSegments("/auth/login/oidc"))
            {
                var redirectUri = $"{_appSettings.RedirectUri}";
                var clientId = $"{_appSettings.ClientId}";
                var domain = $"{_appSettings.Domain}";
                var scope = "openid profile read:appointments";
                var audience = "https://test";
                context.Response.Redirect($"https://{domain}/authorize?client_id={clientId}&response_type=code&scope={scope}&redirect_uri={redirectUri}&state={returnUrl}&audience={audience}");
                return;
            }

            if (loginRequestPath.StartsWithSegments("/auth/login/saml"))
            {
                context.Response.Redirect("https://dev-vrk5vwulx3wfsclz.us.auth0.com/samlp/Nov7Lx4Ggg3mCh2AGsvmaabV7LV40uvv?" + HttpUtility.UrlEncode(returnUrl));
                return;
            }

            await _next(context);
        }
    }
}

