using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using CustomReverseProxy.Middlewares;
using CustomReverseProxy.Models;

namespace CustomReverseProxy
{
    public class Startup
    {
        
	private readonly IConfiguration _configuration;

	public Startup(IConfiguration configuration)
	{
		_configuration = configuration;
	}	
	    
	// This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        
	public void ConfigureServices(IServiceCollection services)
        {
		services.Configure<AppSettings>(_configuration.GetSection("Auth0"));
		
		services.AddControllers();

		services
		.AddSession(options =>
		{
			options.IdleTimeout = TimeSpan.FromMinutes(30); // Set timeout period
			options.Cookie.HttpOnly = true;
			options.Cookie.IsEssential = true;
		});
		
		services.AddDistributedMemoryCache();
		
		services
			.AddAuthentication(options =>
        	{
            	options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
				options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            	options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        	})
			.AddCookie()
			.AddJwtBearer(options =>
        	{	
            	options.Authority = "https://dev-vrk5vwulx3wfsclz.us.auth0.com/";
            	options.Audience = "https://test";
				options.RequireHttpsMetadata = true;
        	});
			services.AddAuthorization(options =>
			{
				options.AddPolicy("AuthenticatedUsers", policy =>
				{
					policy.RequireAuthenticatedUser();
				});
			});


		//services.AddHttpClient("BackendProxy");
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            // app.UseMiddleware<ReverseProxyMiddleware>();

			app.UseRouting();
			//app.UseAuthentication();
			//app.UseAuthorization();

			//app.UseMiddleware<AuthenticationMiddleware>();
			app.UseMiddleware<ReverseProxyMiddleware>();
			app.UseMiddleware<AuthenticationMiddleware>();
			//app.UseMiddleware<AuthenticationMiddleware>();
			//app.UseAuthentication();
			app.UseAuthorization();
			app.UseSession();
			app.UseEndpoints(endpoints => 
			{
				endpoints.MapControllers();
			});

        }
    }
}
