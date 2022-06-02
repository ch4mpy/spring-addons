# spring-security OAuth2 addons

1. [Abstract](#abstract)<br/>
2. [Sample usage](#sample)<br/>
3. [Scopes & Authorities](#scopes-authorities)<br/>

``` xml
    <dependencies>
        <dependency>
            <groupId>com.c4-soft.springaddons</groupId>
            <artifactId>spring-security-oauth2-febmvc-addons</artifactId>
            <version>${com.c4-soft.springaddons.version}</version>
        </dependency>
    </dependencies>
```

<a name="abstract"/>

## What's in there ?

What I propose here are tools to extend spring-security for OAuth2 in spring-boot reactive applications.

`OidcIdAuthenticationToken` is intended to be used with any OpenID authorization server (Keycoak, Auth0, MS Identity Server, ...).
Here are few key features when compared to `JwtAuthenticationToken` or `BearerTokenAuthentication`:
 * sensible default configuration for RESTful APIs secured with OIDC, which can be overridden from properties file:
   - enabled CORS to all origins, methods and headers
   - disabled CSRF
   - 401 instead of redirection to login
   - anonymous enabled
   - authorities from `realm_access.roles` claims. You can provide a list of claims and specify basic post processing (force upper-case and add prefix)
 * no mess up between scopes and authorities
 * principal and credentials are typed with something more actionable than `Object`
 * structure as close as possible to the standard

<a name="sample"/>

## Usage

You might use any OIDC authorization-server (including Keycloak).

``` java
@SpringBootApplication
public class SampleApi {
	public static void main(String[] args) {
		new SpringApplicationBuilder(SampleApi.class).web(WebApplicationType.SERVLET).run(args);
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class WebSecurityConfig {
	  // browse com.c4_soft.springaddons.security.oauth2.config.synchronised.ServletSecurityBeans
	  // for auto-configuration you can override here
	  
	  // ExpressionInterceptUrlRegistryPostProcessor is a bean you might want to provide explicitly for routes neither public nor requiring just isAuthenticated()
	}
}
```
Here is what is configurable from properties file. At least one authorization-server must be configured either in `spring.security.oauth2.resourceserver.jwt.issuer-uri` (single valued) or `com.c4-soft.springaddons.security.authorization-server-locations` (comma separated list)
``` properties
# At least one of the following two must be set
spring.security.oauth2.resourceserver.jwt.issuer-uri=
com.c4-soft.springaddons.security.authorization-server-locations=

# This is where you define a comma separated list of claims to get authorities from
com.c4-soft.springaddons.security.authorities-claims=realm_access.roles
com.c4-soft.springaddons.security.authorities-prefix=
com.c4-soft.springaddons.security.authorities-uppercase=false

# CORS config (per path)
com.c4-soft.springaddons.security.cors[0].path=/**
com.c4-soft.springaddons.security.cors[0].allowedOrigins=*
com.c4-soft.springaddons.security.cors[0].allowedMethods=*
com.c4-soft.springaddons.security.cors[0].allowedHeaders=*
com.c4-soft.springaddons.security.cors[0].exposedHeaders=*

com.c4-soft.springaddons.security.csrf-enabled=false
com.c4-soft.springaddons.security.anonymous-enabled=true
com.c4-soft.springaddons.security.permit-all=/actuator/health/readiness,/actuator/health/liveness,/v3/api-docs/**
com.c4-soft.springaddons.security.redirect-to-login-if-unauthorized-on-restricted-content=false
com.c4-soft.springaddons.security.statless-sessions=true
```

For complete samples, please refer to [`samples` module](https://github.com/ch4mpy/spring-addons/tree/master/samples).

<a name="scopes-authorities"/>

## Scopes and authorites
Why don't I use authentication converters provided by spring-boot?

Mostly because:
- I prefer `OidcIdAuthenticationToken` over `JwtAuthenticationToken`, `BearerTokenAuthentication` (see above) and `KeycloakAuthenticationToken` (too vendor specific)
- I want resource-server to retieve authorities, depending on configuration, from one of the following
  * JWT private claims (like Keycloak `realm_access.roles` and `resource_access.${clientId}.roles`)
  * relational database using a JPA or R2DBC repository (query athorities by end-user `subject`)
   
### Authorities
Authorities define what an end-user is allowed to do with the resource-server. There is no spec about authorities in OpenID nor OAuth2.
It is possible to embed authorities in JWT tokens using private claims, but it's also possible for the resource server to retrieve authorities from elswhere like a database.

### Scopes
As explained in introduction, IMO scopes should be a **mask** on end-user permissions. This mask allows end-user to control what he allows clients to do in his name with resources he (the user) owns.

Lets illustrate how different the relation between scopes and authorities can be with two extreme samples:
 * social-network resource-server with many "untrusted" clients: 
   you need almost a scope per authority to define precisely what the user allows each client can access (age, gender, phone, friends, etc.)
 * resource server with a single trusted client (back-end for mobile or Angular application for instance): no scope at all required. 
   If user authenticates with the client, the client should be able to do whatever the user is alowed to.

### Token-claims embedded authorities

If authorization-server puts already "scoped" authorities in a private claim,
it is then very simple for resource-servers to build authentications as both name and authorities are contained in the token claims but:
 * tokens can come fat when number of clients and resource-servers grows
 * induces high coupling on authorities definitions between authorization and resource servers: 
   updating authorities definition for a service could require modifying the authorization server (at least its database)
   which can be an issue when maintained by another team

### Authorities retrieved from an external source with token subject

Authorization-server acts in 3 steps
1. end-user ID is extracted from the token (`subject` claim is a natural candidate)
2. retrieves authorities fetching an external source (like a DB)
3. restrict authorities according to token scopes (if relevant)

Of course, this requires the resource-server to have more logic to retrieve those authorities from an external source (delegate to a `Repository`?)
and filter it according to scopes (if necessary as some resource-servers with single clients are frequently happy with all-or-nothing strategy) => consumes more resources and takes longer to process
