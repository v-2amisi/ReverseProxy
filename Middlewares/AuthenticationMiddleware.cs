using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System.Threading.Tasks;
using CustomReverseProxy.Models;
using System;

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
            // Check if the request needs authentication
            Console.WriteLine(context.Request.Path);
            Console.WriteLine(context.User.Identity.IsAuthenticated);
            Console.WriteLine(_appSettings.ClientId);
            Console.WriteLine(_appSettings.Domain);
            if (context.Request.Path.StartsWithSegments("/app1") &&
                !context.User.Identity.IsAuthenticated)
            {
                // Redirect to Auth0 for authentication
                var redirectUri = $"{_appSettings.RedirectUri}";
                var clientId = $"{_appSettings.ClientId}";
                var domain = $"{_appSettings.Domain}";
                var scope = "openid read:appointments";
                context.Response.Redirect($"https://{domain}/authorize?client_id={clientId}&response_type=code&scope={scope}&redirect_uri={redirectUri}&state=12345");
                return;
            }

            await _next(context);
        }
    }
}

