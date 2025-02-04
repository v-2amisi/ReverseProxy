using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace CustomReverseProxy.Middlewares
{
    public class ReverseProxyMiddleware
    {
        private static readonly HttpClient _httpClient = new HttpClient();
        private readonly RequestDelegate _next;
        //private readonly string _oidcCallbackPath = "/callback";

        public ReverseProxyMiddleware(RequestDelegate next)
        {
            _next = next;
        }



        public async Task Invoke(HttpContext context)
        {
            if (!context.Session.IsAvailable)
            {
                await _next(context);
                return;
            }
            
            string requestedUrl = context.Request.Path;

            // Step 1: Determine if authentication is needed
            //bool isAuthenticated = context.Session.GetString("IsAuthenticated") == "true";
            //Console.WriteLine("Calling build target uri");
            //Console.WriteLine(context.User.Identity.IsAuthenticated);
            var targetUri = BuildTargetUri(context);
            Console.WriteLine(targetUri.ToString());
            Console.WriteLine(targetUri.ToString().Contains("/auth/login"));
            if (targetUri != null && !targetUri.ToString().Contains("/auth/login"))
            {
                Console.WriteLine($"Calling build target message: {context.User.Identity.IsAuthenticated}");
                var targetRequestMessage = CreateTargetMessage(context, targetUri);

                using (var responseMessage = await _httpClient.SendAsync(targetRequestMessage, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted))
                {
                    context.Response.StatusCode = (int)responseMessage.StatusCode;
                    Console.WriteLine($"Calling copy from target resp headers: {context.User.Identity.IsAuthenticated}");
                    CopyFromTargetResponseHeaders(context, responseMessage);
                    await responseMessage.Content.CopyToAsync(context.Response.Body);
                }
                return;
            }
            else
            {
                var loginRedirectPath = targetUri.AbsolutePath + targetUri.Query;
                Console.WriteLine(loginRedirectPath);
                context.Response.Redirect(loginRedirectPath);
                return;
            }

            await _next(context);
        }


        private HttpRequestMessage CreateTargetMessage(HttpContext context, Uri targetUri)
        {
            var requestMessage = new HttpRequestMessage
            {
                RequestUri = targetUri,
                Method = new HttpMethod(context.Request.Method)
            };

            // Copy headers from the original request
            foreach (var header in context.Request.Headers)
            {
                if (!requestMessage.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray()))
                {
                    requestMessage.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
                }
            }
            Console.WriteLine($"Target message built: {context.User.Identity.IsAuthenticated}");
            return requestMessage;
        }

        private Uri BuildTargetUri(HttpContext context)
        {
            // Configure routing to backend applications
            bool isAuthenticated = context.Session.GetString("IsAuthenticated") == "true";
            if (context.Request.Path.StartsWithSegments("/app1") && !isAuthenticated)
            {
                string returnUrl = "https://ec2-54-82-60-31.compute-1.amazonaws.com:5001";
                context.Session.SetString("returnUrl", returnUrl);
                
                // Redirect user to Authentication Middleware (/auth/login)
                return new Uri($"https://ec2-54-82-60-31.compute-1.amazonaws.com:5443/auth/login?redirect_uri={returnUrl}");

                //await _next(context);
                
            }
            else
            {
                Console.WriteLine("TargetUri: https://ec2-54-82-60-31.compute-1.amazonaws.com:5001");
                Console.WriteLine(context.User.Identity.IsAuthenticated);
                return new Uri("https://ec2-54-82-60-31.compute-1.amazonaws.com:5001");
            }
            if (context.Request.Path.StartsWithSegments("/app2"))
            {
                return new Uri("https://ec2-54-82-60-31.compute-1.amazonaws.com:5001");
            }

            return null;
        }

        private void CopyFromTargetResponseHeaders(HttpContext context, HttpResponseMessage responseMessage)
        {
            foreach (var header in responseMessage.Headers)
            {
                context.Response.Headers[header.Key] = header.Value.ToArray();
            }

            foreach (var header in responseMessage.Content.Headers)
            {
                context.Response.Headers[header.Key] = header.Value.ToArray();
            }
            Console.WriteLine($"copied target response headers: {context.User.Identity.IsAuthenticated}");
            context.Response.Headers.Remove("transfer-encoding");
        }
    }


}


//Earlier code

/*
        public async Task Invoke(HttpContext context)
        {
            //Console.WriteLine("reverseproxy middleware: " + context.Session.IsAvailable);
            if (!context.Session.IsAvailable)
            {
                await _next(context);
                return;
            }
            
            string requestedUrl = context.Request.Path;

            // Step 1: Determine if authentication is needed
            bool isAuthenticated = context.Session.GetString("IsAuthenticated") == "true";
            Console.WriteLine("reverseproxy middleware isauthenticated: " + isAuthenticated);
            //bool.TryParse(context.Session.GetString("IsAuthenticated"), out bool authenticated);
            // bool authenticated = context.Session.GetString("IsAuthenticated");
            //Console.WriteLine("context.Session.GetString('IsAuthenticated'): " + authenticated);
            string returnUrl = "https://ec2-54-82-60-31.compute-1.amazonaws.com:5001";
            if (IsProtectedRoute(requestedUrl) && !isAuthenticated){
                //string returnUrl = context.Request.Path + context.Request.QueryString;
                //string returnUrl = "https://ec2-54-82-60-31.compute-1.amazonaws.com:5001";
                context.Session.SetString("returnUrl", returnUrl);
                
                // Redirect user to Authentication Middleware (/auth/login)
                context.Response.Redirect($"/auth/login?redirect_uri={returnUrl}");
                return;
            }
            else
            {
                context.Response.Redirect(returnUrl);
            }

            await _next(context);
        }

        private bool IsProtectedRoute(string url)
        {
            return url.StartsWith("/app1");
        }

*/


