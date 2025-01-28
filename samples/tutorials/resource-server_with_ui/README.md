# Mix OAuth2 Client and Resource Server Configurations in a Single Application
The aim here is to **configure a Spring back-end as both OAuth2 client and resource server while allowing users to authenticate among a list of heterogeneous trusted authorization-servers**: a local Keycloak realm & an Auth0 instance in the cloud.

## 0. Disclaimer
There are quite a few samples, and all are part of CI to ensure that sources compile and all tests pass. Unfortunately, this README is not automatically updated when source changes. Please use it as a guidance to understand the source. **If you copy some code, be sure to do it from the source, not from this README**.

## 1. Preamble
We'll define two distinct and ordered security filter-chains: 
- the 1st with client configuration, with login, logout, and a security matcher limiting it to UI resources
- the 2nd with resource server configuration. As it has no security matcher and a higher order, it intercepts all requests that were not matched by the 1st filter chain and acts as default for all the remaining resources (REST API).

It is important to note that in this configuration, **the browser is not an OAuth2 client**: it is secured with regular sessions. As a consequence, **CSRF and BREACH protection must be enabled** in the client filter-chain.

The UI being secured with session cookies and the REST end-points with JWTs, the Thymeleaf `@Controller` internally uses `RestClient` to fetch data from the API and build the model for the template, authorizing its requests with tokens stored in session.

The different providers are configured in different Spring profiles. If we decided to have amore than on `provider` in the main profile, and a `registration` with `authorization_code` for each provider, **we'd have to require the user to log out before he can log in with a different `registration`**. That's because Spring Security is designed to contain only one `Authentication` in the security context, and because in the case of `oauth2Login` this `Authentication` is bound to a given `registration`, 

To run the sample, be sure your environment meets [tutorials prerequisites](https://github.com/ch4mpy/spring-addons/blob/master/samples/tutorials/README.md#prerequisites).

## 2. Scenario Details
We will implement a Spring back-end with
- a resource server (REST API)
  * accepting identities from 3 different issuers (Keycloak, Auth0 and Cognito)
  * session-less (with CSRF disabled)
  * returning 401 (unauthorized) if a request is unauthorized
  * serving greeting messaged customized with authenticated username and roles
  * defining access-control to the REST end-points exposed by `@Controllers` as well as Swagger REST resources (OpenAPI spec) and actuator 
- a Thymeleaf client for the above resource server
  * asking the user to login
  * sessions are required as requests from browsers won't be authorized with a Bearer token (CSRF protection should be activated too)
  * returning the default 302 (redirect to login) if the user has no session yet
  * an index page, loaded after authentication, with links to Thymeleaf page and Swagger-UI index
  * defining access-control to all OAuth2 client & UI resources: login, logout, authorization callbacks and Swagger-UI
  * a "greet" page where the user can
    - get a greeting for each of the identity providers he is connected to
    - add an identity from one of the configured identity providers he is not authenticated against yet
    - logout from the identity providers he is connected to either individually or all of it
    - invalidate his session from the Thymeleaf client without disconnecting from identity providers

## 3. Project Initialisation
We'll start a spring-boot 3 project from https://start.spring.io/ with these dependencies:
- lombok
- spring-boot-starter-web (used by both REST API and UI servlets)
- spring-boot-starter-thymeleaf
- spring-boot-starter-actuator

And then add those dependencies:
- [`spring-addons-starter-oidc`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-starter-oidc)
- [`spring-addons-starter-rest`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-starter-rest)
- [`spring-addons-starter-oidc-test`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-starter-oidc-test) with `test` scope
```xml
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starter-oidc</artifactId>
    <version>${spring-addons.version}</version>
</dependency>
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starter-rest</artifactId>
    <version>${spring-addons.version}</version>
</dependency>
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starter-oidc-test</artifactId>
    <version>${spring-addons.version}</version>
    <scope>test</scope>
</dependency>
```

## 4. Web-Security Configuration
This tutorial uses `spring-addons-starter-oidc` which auto-configures two `SecurityFilterChain` beans based on properties file (one with `oauth2ResourceServer` and one with `oauth2Login`). **These security filter-chains are not explicitly defined in security-conf, but are there!**

### 4.1. Application Properties
Refer to the sources.

The properties under `rest` define the configuration for a `RestClient` bean named `greetClient` and using a `registration` with client-credentials to authorize its requests to our REST API.

Don't forget to update the issuer URIs as well as client ID & secrets with your own (or to override it with command line arguments, environment variables or whatever).

#### 4.2. OAuth2 Security Filter-Chain
**We have absolutely no Java code to write.**

### 4.3. RP-Initiated Logout
This one is tricky. It is important to have in mind that each user has a session on our client but also on each authorization server.

If we invalidate only the session on our client, it is very likely that the next login attempt with the same browser will complete silently. For a complete logout, **both client and authorization sessions should be terminated**.

OIDC specifies two logout protocols:
- [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) where a client asks the authorization-server to terminate a user session
- [back-channel logout](https://openid.net/specs/openid-connect-backchannel-1_0.html) where the authorization-server brodcasts a logout event to a list of registered clients so that each can terminate its own session for the user

Here, we cover only the RP-Initiated Logout.

## 5. Resource Server Components
As username and roles are already mapped, it's super easy to build a greeting containing both from the `Authentication` instance in the security-context:
```java
@RestController
@RequestMapping("/api")
@PreAuthorize("isAuthenticated()")
public class ApiController {
    @GetMapping("/greet")
    public String getGreeting(JwtAuthenticationToken auth) {
        return "Hi %s! You are granted with: %s.".formatted(auth.getName(), auth.getAuthorities());
    }
}
```

## 6. Client Components and Resources
We'll need a few resources: a static index as well as a a pair of templates with a controllers to serve it.

What we'll see here is specific to multi-tenancy needs. With a single identity provider, we'd redirect the user directly to the authentication endpoint instead of displaying a page to choose login options and configure the standard logout endpoint with a `LogoutSuccessHandler` adapted to the authorization server logout endpoint (see `SpringAddonsOAuth2LogoutSuccessHandler` Javadoc).

Refer to sources for UI controllers and tempaltes.

## 7. Conclusion
In this tutorial we saw how to configure different security filter-chains and select to which routes each applies. We set up
- an OAuth2 client filter-chain with login, logout and sessions (and CSRF protection) for UI
- a state-less (neither session nor CSRF protection) filter-chain for the REST API

We also saw how handy `spring-addons-webmvc-jwt-resource-server` and `spring-addons-webmvc-client` are when it comes to configuring respectively OAuth2 resource servers and OAuth2 clients.
