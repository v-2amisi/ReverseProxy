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
            
            //string requestedUrl = context.Request.Path;
            if(context.Request.Path.StartsWithSegments("/callback") || context.Request.Path.StartsWithSegments("/auth"))
            {
                await _next(context);
                return;
            }
            // Step 1: Determine if authentication is needed
            //bool isAuthenticated = context.Session.GetString("IsAuthenticated") == "true";
            //Console.WriteLine("Calling build target uri");
            //Console.WriteLine(context.User.Identity.IsAuthenticated);
            var (targetUri, isRedirect) = BuildTargetUri(context);
            //Console.WriteLine("Build targeturi returned: " + targetUri);
            //Console.WriteLine("Build targeturi returned isRedirect as: " + isRedirect);
            //if(targetUri.AbsolutePath == "/") return;
            //string requestedUrl = context.Request.Path;
            //Console.WriteLine(targetUri.ToString());
            //Console.WriteLine(targetUri.ToString().Contains("/auth/login"));
            if (isRedirect)
            {
                var redirectPath = targetUri.Scheme + "://" + targetUri.Host + ":5443" + targetUri.AbsolutePath + targetUri.Query;
                //var redirectPath = context.Request.Scheme + "://" + context.Request.Host + context.Request.Path + context.Request.QueryString;
                Console.WriteLine("ReverseProxy middleware determined a redirect to: " + redirectPath);
                context.Response.Redirect(redirectPath);
                return;
            }
            else
            {
                //Console.WriteLine($"Calling build target message: {context.User.Identity.IsAuthenticated}");
                //Console.WriteLine("backendTarget: " + context.Request.Scheme + "://" + context.Request.Host + context.Request.Path + context.Request.QueryString);
                //var backendTarget = new Uri(context.Request.Scheme + "://" + context.Request.Host + context.Request.Path + context.Request.QueryString);
                var backendTarget = targetUri;
                var targetRequestMessage = CreateTargetMessage(context, backendTarget);

                using (var responseMessage = await _httpClient.SendAsync(targetRequestMessage, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted))
                {
                    context.Response.StatusCode = (int)responseMessage.StatusCode;
                    //Console.WriteLine($"Calling copy from target resp headers: {context.User.Identity.IsAuthenticated}");
                    CopyFromTargetResponseHeaders(context, responseMessage);
                    
                    // Modify the response sent to browser before sending
                    var responseToModify = await responseMessage.Content.ReadAsStringAsync();
                    if (responseMessage.Content.Headers.ContentType?.MediaType == "text/html")
                    {
                        var dataToAdd = "<div>ID Token: " + context.Session.GetString("id_token") + "</br>";
                        List<string> idTokenClaims = new List<string>(context.Session.GetString("AllIDTokenClaims").Split(';'));
                        foreach (var idTokenClaim in idTokenClaims)
                        {
                            //List<string> claimSplit = new List<string>(idTokenClaim.Split(","));
                            List<string> claimSplit = new List<string>(idTokenClaim.Split(':'));
                            //List<string> claimValueSplit = new List<string>(claimSplit[1].Split(":"));
                            Console.WriteLine(claimSplit[0] + ": " + claimSplit[1]);
                            dataToAdd += "<p>" + claimSplit[0] + ": " + claimSplit[1] + "</p></br>";
                        }
                        dataToAdd += "</div>";

                        /*
                        dataToAdd += "<div>Access Token: " + context.Session.GetString("access_token") + "</br>";
                        List<string> accessTokenClaims = new List<string>(context.Session.GetString("AllAccessTokenClaims").Split(';'));
                        foreach (var accessTokenClaim in accessTokenClaims)
                        {
                            List<string> claimSplit = new List<string>(accessTokenClaim.Split(':'));
                            //List<string> claimNameSplit = new List<string>(claimSplit[0].Split(":"));
                            //List<string> claimValueSplit = new List<string>(claimSplit[1].Split(":"));
                            dataToAdd += "<p>" + claimSplit[0] + ": " + claimSplit[1] + "</p></br>";
                        }
                        dataToAdd += "</div></br>";
                        */
                        responseToModify += dataToAdd;
                    }
                    // End of modify section

                    await context.Response.WriteAsync(responseToModify, Encoding.UTF8);
                    //await responseMessage.Content.CopyToAsync(context.Response.Body);
                }
                return;
            }
            /*
            else
            {
                var loginRedirectPath = targetUri.AbsolutePath + targetUri.Query;
                Console.WriteLine(loginRedirectPath);
                context.Response.Redirect(loginRedirectPath);
                return;
            }
            */

            await _next(context);
        }

        private bool IsProtectedRoute(string url)
        {
            //bool isAuthenticated = context.Session.GetString("IsAuthenticated") == "true";
            return url.StartsWith("/app1");
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
            //Console.WriteLine($"Target message built: {context.User.Identity.IsAuthenticated}");
            return requestMessage;
        }

        private (Uri, bool) BuildTargetUri(HttpContext context)
        {
            // Configure routing to backend applications
            //bool isAuthenticated = context.Session.GetString("IsAuthenticated") == "true";
            var requestedPath = context.Request.Path;

            if (IsProtectedRoute(requestedPath))
            {
                Console.WriteLine("context.Session.GetString('IsAuthenticated'): " + context.Session.GetString("IsAuthenticated"));
                bool isAuthenticated = context.Session.GetString("IsAuthenticated") == "True";
                //Console.WriteLine("isAuthenticated after callback: " + isAuthenticated);
                //Console.WriteLine(context.Session.GetString("IsAuthenticated") == "True");
                string returnUrl = "https://ec2-54-82-60-31.compute-1.amazonaws.com:5001";
                if(!isAuthenticated){
                    context.Session.SetString("returnUrl", returnUrl);
                    //Console.WriteLine("Getting redirected to authentication endpoint /auth/login");
                    // Redirect user to Authentication Middleware (/auth/login)
                    return (new Uri($"https://ec2-54-82-60-31.compute-1.amazonaws.com:5443/auth/login?redirect_uri={returnUrl}"), "True" == "True");
                }
                else {
                    return (new Uri(returnUrl), "True" == "False");
                }
                
            }
            
            if (requestedPath.StartsWithSegments("/app2"))
            {
                return (new Uri("https://ec2-54-82-60-31.compute-1.amazonaws.com:5001"), "True" == "False");
            }
/*
            if (requestedPath.StartsWithSegments("/callback"))
            {
                var callbackUri = context.Request.Scheme + "://" + context.Request.Host + context.Request.Path + context.Request.QueryString;
                Console.WriteLine("ReverseProxy callback uri returned: " + callbackUri);
                return (new Uri(callbackUri), "true" == "true");
            }
*/
            //if(requestedPath.StartsWithSegments("/auth/login") || requestedPath.StartsWithSegments("/callback"))
            //{
                var requestedUri = "https://ec2-54-82-60-31.compute-1.amazonaws.com:5001" + context.Request.Path + context.Request.QueryString;
                return (new Uri(requestedUri), "True" == "False");
            //}

            //return null;
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
            //Console.WriteLine($"copied target response headers: {context.User.Identity.IsAuthenticated}");
            context.Response.Headers.Remove("transfer-encoding");
            context.Response.Headers.Remove("Content-Length");
            context.Response.Headers["x-auth0-access-token"] = context.Session.GetString("access_token");
            context.Response.Headers["x-auth0-id-token"] = context.Session.GetString("id_token");
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


