# **Reverse Proxy with Authentication Middleware (OIDC and SAML Support)**  

This repository provides a modular Reverse Proxy implementation using **ASP.NET Core (3.1)**. It features:  
- Reverse Proxy Middleware for routing requests to backend services.  
- Authentication Middleware for handling OIDC and SAML authentication.  
- Callback Controller for processing authorization code responses and handling token retrieval.  
- Complete session management and redirection to originally requested protected resources.  
- Support for modifying request/response headers and injecting additional content into responses.  

---

## **Table of Contents**
1. [Overview](#overview)  
2. [Architecture](#architecture)  
3. [Project Structure](#project-structure)  
4. [Configuration](#configuration)  
5. [Middleware Components](#middleware-components)  
6. [Callback Controller](#callback-controller)  
7. [Session Management](#session-management)  


---

## **Overview**  
This project implements a Reverse Proxy with authentication for secure access to backend services. The Reverse Proxy intercepts requests and determines if they require authentication. If authentication is needed, the request is redirected to the appropriate identity provider (OIDC or SAML). After successful authentication, the originally requested resource is served.  

---

## **Architecture**  
### **Flow Diagram**  
```mermaid
graph TD;
    A[Incoming Request] --> B{Reverse Proxy Middleware};
    B -->|Unprotected| C[Backend Service];
    B -->|Protected| D[Authentication Middleware];
    D --> E[Callback Controller];
    E --> F[Token Retrieval];
    F --> G[Session Management];
    G --> H{Authenticated?};
    H -->|Yes| I[Proxy to Requested Resource];
    H -->|No| D;
```

---

## **Project Structure**  
```
/Middlewares
    - ReverseProxyMiddleware.cs
    - AuthenticationMiddleware.cs
/Controllers
    - CallbackController.cs
/Models
    - AppSettings.cs
/Startup.cs
/Program.cs
appSettings.json
```

### **Key Components**  
- **ReverseProxyMiddleware.cs**: Handles routing of requests to backend services and ensures proper response handling (headers and content modification).  
- **AuthenticationMiddleware.cs**: Intercepts protected requests and redirects unauthenticated users to the authentication provider.  
- **CallbackController.cs**: Handles the OIDC/SAML callback, processes the authorization code, retrieves tokens, and establishes the authenticated user session.  
- **Startup.cs**: Configures middleware pipeline, services, and session management.  
- **Program.cs**: Entry point of the application.
- **appSettings.json: Configures kestrel server with dns name for the host, certificate for SSL and authentication configuration (Authentication is configured with Auth0 in this sample). 

---

## **Configuration**  

### **IdP Configuration**
In this setup Auth0 is configured as the identity store, OIDC provider and OAuth 2.0 token service provider. Okta is used as a federation provider. The configuration is described below:

- Okta (Federated IdP)
    - Create a SAML application
        - Navigate to Applications and click Add Application.
        - Choose Web as the platform.
        - Under Sign on method, select SAML 2.0.
        - Click Next.
    - Configure SAML settings
        - Single sign on URL: You’ll set this later in Auth0 or use a temporary URL (e.g., https://YOUR_DOMAIN/callback), as Auth0 will provide the callback configuration.
        - Audience URI (SP Entity ID): Use a unique identifier such as your Auth0 client’s identifier (for example, https://YOUR_AUTH0_DOMAIN/saml/metadata or a value provided by Auth0).
        - Attribute Statements (optional): Define mappings for user attributes (e.g., email, name, roles).
        - Click Next and then Finish to create the application.
        - Once created, note the Identity Provider metadata URL or download the metadata XML from Okta. This metadata contains the SSO URL and the X.509 certificate you’ll need later.
- Auth0 (Identity Provider)
    - Create an OIDC web application
        - In the left-hand menu, click on "Applications".
        - Click the "Create Application" button.
        - In the "Create Application" dialog:
        - Name: Enter a name for your application (e.g., "My OIDC Web App").
        - Application Type: Choose "Regular Web Application".
        - Click "Create".
    - Configure application settings
        - Configure callback URLs (Callback url for the reverse proxy application).
        - Optionally configure logout URLs (Home page for the reverse proxy application).
    - Review the application settings to be used in the reverse proxy configuration
        - Domain (tenantname.us.auth0.com)
        - Client ID: Identifier for the application
        - Client Secret: Application secret key
        - Configure appSettings.json on the reverse proxy project using the values discovered above.
    - Configure an API and authorize the application created above
        - In the left-hand menu, click on "APIs".
        - Click the "Create API" button.
        - In the Create API dialog:
        - Name: Enter a name for your API (e.g., "My Custom API").
        - Identifier: Provide a unique identifier (a URL-like string, e.g., https://myapi.example.com). This    identifier is used as the audience when requesting access tokens.
        - Signing Algorithm: Choose an algorithm (typically RS256 is recommended).
        - Click "Create".
        - In your newly created API’s settings, go to "Permissions" (or "Scopes") section.
        (Note: Depending on the Auth0 dashboard version, you might see a section called "Allowed Scopes" or simply "Scopes".)
        - Click "Add Scopes" (or similar) to define custom scopes.
        - For each scope, specify:
        Scope Name: A short name that represents the permission (e.g., read:data or write:data).
        Description: A brief description of what the scope allows (e.g., "Read data from My Custom API" or "Write data to My Custom API").
        - Save your changes.
        - In the API's settings, go to "Machine to Machine Applications" and make sure that the application created earlier is Authorized with Permissions granted to the scopes defined.
    - Create an Enterprise SAML connection
        - Go to Connections -> Enterprise.
        - In the Enterprise connections list, look for SAML 2.0.
        - Fill in the connection fields using information from Okta:
            - Name: Provide a name for this connection (e.g., okta-saml).
            - Display Name: (Optional) The name users see on the login screen.
            - Metadata URL or XML: If you have the Okta metadata URL, enter it here (e.g., https://YOUR_OKTA_DOMAIN/app/YOUR_APP_ID/sso/saml/metadata). Alternatively, paste the downloaded metadata XML.
            - Issuer (Entity ID): Set this to the Audience URI you configured in Okta (or use the value provided by Auth0 for your connection).
            - Sign In URL: This should be taken from the metadata (SSO URL from Okta).
            - Signing Certificate: This is the X.509 certificate from Okta’s metadata. If it’s not automatically populated from the metadata URL, paste the certificate manually.
            - Mapping: Optionally, map SAML attributes to Auth0 user profile fields (e.g., map SAML attribute EmailAddress to Auth0’s email).
            - Save your connection.

### **PFX Certificate generation**
- On Mac
	- Open terminal and use the openssl command to generate a private key and a self-signed certificate with a dns name.
	```bash
	openssl req -x509 -newkey rsa:2048 -keyout private.key -out certificate.crt -days 365 -nodes \
	  -subj "/C=US/ST=California/L=San Francisco/O=MyOrganization/CN=mydomain.com" \
	  -addext "subjectAltName=DNS:example.org.com,DNS:example.org.com"
	
	```
	- Convert the certificat to PFX format
	```bash
	openssl pkcs12 -export -out certificate.pfx -inkey private.key -in certificate.crt -passout pass:yourpassword
	
	```

 - On Windows
   	- Open powershell and generate a self-signed certificate using the following command
	```powershell
	$cert = New-SelfSignedCertificate -DnsName "yourdomain.com" -CertStoreLocation "Cert:\LocalMachine\My"
	
	```
 	- Export the certificate as a PFX file
  	```powershell
	$CertPassword = ConvertTo-SecureString -String "yourpassword" -Force -AsPlainText
	Export-PfxCertificate -Cert "Cert:\LocalMachine\My\$($cert.Thumbprint)" -FilePath "C:\path\to\certificate.pfx" -Password $CertPassword
	```



### **appSettings.json Configuration**
Add kestrel server configuration, certificate configuration and Auth0 configuration in `appSettings.json`.
```json
"Auth0": {
    "Domain":"example.us.auth0.com",
    "ClientId":"clientId",
    "ClientSecret": "clientSecret",
    "RedirectUri":"https://example.org.com/callback"
 },
  "Kestrel": {
    "Endpoints": {
      "Http": {
        "Url": "http:/example.org.com"
      },
      "Https": {
        "Url": "https://example.org.com",
	"Certificate": {
		"Path": "pathToPFXFile",
		"Password": "passwordForPFXFile"
      }
  }
```

### **Reverse Proxy Middleware Configuration**
Add your backend service routes and define which paths require authentication in `ReverseProxyMiddleware.cs`.  
```csharp
if (!context.Request.Path.StartsWithSegments("/auth") && !context.Request.Path.StartsWithSegments("/callback"))
{
    // Process request normally or redirect to authentication
}
```

### **Authentication Middleware**  
Configures OIDC or SAML for handling user authentication.  

### **Callback Endpoint**  
`/callback`: This endpoint processes the authorization code and retrieves tokens for establishing a session.

---

## **Middleware Components**  

### **ReverseProxyMiddleware.cs**  
```csharp
public class ReverseProxyMiddleware
{
    private readonly RequestDelegate _next;

    public ReverseProxyMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task Invoke(HttpContext context)
    {
        if (context.Request.Path.StartsWithSegments("/callback"))
        {
            await _next(context);  // Pass to CallbackController
            return;
        }

        // Proxy logic: modify request, add headers, etc.
    }
}
```

### **AuthenticationMiddleware.cs**  
```csharp
public class AuthenticationMiddleware
{
    private readonly RequestDelegate _next;

    public AuthenticationMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task Invoke(HttpContext context)
    {
        if (!context.User.Identity.IsAuthenticated)
        {
            context.Response.Redirect("/auth/login");
            return;
        }

        await _next(context);
    }
}
```

---

## **Callback Controller**  
- Handles the `/callback` endpoint to process the authorization code and retrieve tokens.
- Decodes tokens, parses and stores in session.


## **Session Management**  
- Uses `HttpContext.Session` to store token data and authentication status.  
- Ensures session persistence across middleware and controllers.   

---

## **Running the Application**  

1. **Clone the Repository:**  
   ```bash
   git clone https://github.com/v-2amisi/ReverseProxy.git
   cd ReverseProxy
   ```

2. **Install Dependencies:**  
   Ensure you have .NET Core 3.1 SDK installed.  

3. **Build and Run the Application:**  
   ```bash
   dotnet restore
   dotnet build
   dotnet run
   ```

4. **Access the Application:**  
   Visit `https://localhost:5000` in your browser.  

---

## **Future Enhancements**  
- Add support for SAML.  
- Implement OAuth client credentials flow for reverse proxy to act as a client for internal authorization server.  
- Add role-based authorization.  

---


