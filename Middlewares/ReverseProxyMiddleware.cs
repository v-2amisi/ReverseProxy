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
            if(context.Request.Path.StartsWithSegments("/callback") || context.Request.Path.StartsWithSegments("/auth") || context.Request.Path.StartsWithSegments("/saml"))
            {
                await _next(context);
                return;
            }
            
            var (targetUri, isRedirect) = BuildTargetUri(context);
            
            if (isRedirect)
            {
                var redirectPath = targetUri.Scheme + "://" + targetUri.Host + ":5443" + targetUri.AbsolutePath + targetUri.Query;
                context.Response.Redirect(redirectPath);
                return;
            }
            else
            {
                var backendTarget = targetUri;
                var targetRequestMessage = CreateTargetMessage(context, backendTarget);

                using (var responseMessage = await _httpClient.SendAsync(targetRequestMessage, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted))
                {
                    context.Response.StatusCode = (int)responseMessage.StatusCode;
                    CopyFromTargetResponseHeaders(context, responseMessage);
                    
                    // Modify the response sent to browser before sending
                    var responseToModify = await responseMessage.Content.ReadAsStringAsync();
                    var authType = context.Session.GetString("AuthType");
                    if (responseMessage.Content.Headers.ContentType?.MediaType == "text/html")
                    {
                        if(authType == "OIDC")
                        {
                            var dataToAdd = "<div>ID Token: " + context.Session.GetString("id_token") + "</br>";
                            List<string> idTokenClaims = new List<string>(context.Session.GetString("AllIDTokenClaims").Split(';'));
                            foreach (var idTokenClaim in idTokenClaims)
                            {
                                List<string> claimSplit = new List<string>(idTokenClaim.Split(':'));
                                dataToAdd += "<p>" + claimSplit[0] + ": " + claimSplit[1] + "</p></br>";
                            }
                            dataToAdd += "</div>";

                            responseToModify += dataToAdd;
                        }
                        if(authType == "SAML")
                        {
                            var dataToAdd = context.Session.GetString("SAMLClaims");

                            responseToModify += dataToAdd;
                        }
                        // End of modify section

                        await context.Response.WriteAsync(responseToModify, Encoding.UTF8);
                    }
                    
                    
                }
                return;
            }
            

            await _next(context);
        }

        private bool IsProtectedRoute(string url)
        {
            
            return url.StartsWith("/app1");
        }

        private bool IsSAMLRoute(string url)
        {
            
            return url.StartsWith("/app2");
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
            
            return requestMessage;
        }

        private (Uri, bool) BuildTargetUri(HttpContext context)
        {
            var requestedPath = context.Request.Path;

            if (IsProtectedRoute(requestedPath))
            {
                Console.WriteLine("context.Session.GetString('IsAuthenticated'): " + context.Session.GetString("IsAuthenticated"));
                bool isAuthenticated = context.Session.GetString("IsAuthenticated") == "True";
                
                string returnUrl = "https://ec2-54-82-60-31.compute-1.amazonaws.com:5001";
                if(!isAuthenticated){
                    context.Session.SetString("returnUrl", returnUrl);
                    return (new Uri($"https://ec2-54-82-60-31.compute-1.amazonaws.com:5443/auth/login/oidc?redirect_uri={returnUrl}"), "True" == "True");
                }
                else {
                    return (new Uri(returnUrl), "True" == "False");
                }
                
            }

            if(IsSAMLRoute(requestedPath))
            {
                bool isAuthenticated = context.Session.GetString("IsAuthenticated") == "True";
                string returnUrl = "https://ec2-54-82-60-31.compute-1.amazonaws.com:5443/app2";
                if(!isAuthenticated){
                    context.Session.SetString("returnUrl", returnUrl);
                    return (new Uri($"https://ec2-54-82-60-31.compute-1.amazonaws.com:5443/auth/login/saml?redirect_uri={returnUrl}"), "True" == "True");
                }
                else {
                    return (new Uri(returnUrl), "True" == "False");
                }
            }
            
            if (requestedPath.StartsWithSegments("/app2"))
            {
                return (new Uri("https://ec2-54-82-60-31.compute-1.amazonaws.com:5001"), "True" == "False");
            }

            var requestedUri = "https://ec2-54-82-60-31.compute-1.amazonaws.com:5001" + context.Request.Path + context.Request.QueryString;
            return (new Uri(requestedUri), "True" == "False");
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
            
            context.Response.Headers.Remove("transfer-encoding");
            context.Response.Headers.Remove("Content-Length");
            context.Response.Headers["x-auth0-access-token"] = context.Session.GetString("access_token");
            context.Response.Headers["x-auth0-id-token"] = context.Session.GetString("id_token");
        }
    }


}