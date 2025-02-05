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
            // Check if the request needs authentication
            //Console.WriteLine(context.Request.Path);
            //Console.WriteLine(context.User.Identity.IsAuthenticated);
            //Console.WriteLine(_appSettings.ClientId);
            //Console.WriteLine(_appSettings.Domain);
            Console.WriteLine("Auth Middleware Is Authenticated: " + context.Session.GetString("IsAuthenticated"));
            Console.WriteLine("Auth middleware Path: " + context.Request.Path);
            Console.WriteLine("Auth middleware response location: " + context.Response.Headers["Location"].ToString());
            //var loginRequestPath = context.Response.Headers["Location"].ToString();
            var loginRequestPath = context.Request.Path;
            if (loginRequestPath.StartsWithSegments("/auth/login"))
            {
                Console.WriteLine("Auth Middleware: Login process started.");
                //var loginRequestPathUri = new Uri(loginRequestPath);
                string returnUrl = context.Request.QueryString;
                Console.WriteLine("Auth Middleware, redirect URI: " + returnUrl);
                if (string.IsNullOrEmpty(returnUrl)) returnUrl = "/";
                // Redirect to Auth0 for authentication
                var redirectUri = $"{_appSettings.RedirectUri}";
                var clientId = $"{_appSettings.ClientId}";
                var domain = $"{_appSettings.Domain}";
                var scope = "openid profile read:appointments";
                context.Response.Redirect($"https://{domain}/authorize?client_id={clientId}&response_type=code&scope={scope}&redirect_uri={redirectUri}&state={returnUrl}");
                return;
            }

            await _next(context);
        }
    }
}

