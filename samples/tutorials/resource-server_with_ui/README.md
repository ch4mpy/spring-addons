# Mix OAuth2 Client and Resource-Server Configurations in a Single Application
The aim here is to **configure a Spring back-end as both OAuth2 client and resource-server while allowing users to authenticate among a list of heterogeneous trusted authorization-servers**: a local Keycloak realm as well as remote Auth0 and Cognito instances.

## 1. Preamble
It is important to note that in this configuration, the browser **is not an OAuth2 client**: it is secured with regular sessions, which must be enabled on the `SecurityFilterChain` dedicated to login, logout and UI resources.

From the security point of view, the application is split in two parts
- OAuth2 client which handles OAuth2 flows and renders UI elements
- OAuth2 resource-server which is the REST API.

To run the sample, be sure your environment meets [tutorials prerequisites](https://github.com/ch4mpy/spring-addons/blob/master/samples/tutorials/README.md#prerequisites).

## 2. Scenario Details
We will implement a Spring back-end with
- a resource-server (REST API)
  * accepting identities from 3 different issuers (Keycloak, Auth0 and Cognito)
  * session-less (with CSRF disabled)
  * returning 401 (unauthorized) if a request is unauthorized
  * serving greeting messaged customized with authenticated username and roles
  * defining access-control to the REST end-points exposed by `@Controllers` as well as Swagger REST resources (OpenAPI spec) and actuator 
- a Thymeleaf client for the above resource-server
  * asking the user to choose between the 3 authentication sources trusted by the resource-server
  * sessions are required as requests from browsers won't be authorized with a Bearer token (CSRF protection should be activated too)
  * returning the default 302 (redirect to login) if the user has no session yet
  * an index page, loaded after authentication, with links to Thymeleaf page and Swager-UI index
  * a login page to select an authorization-server (aka tenant): a local Keycloak realm along with remote Auth0 and Cognito instances
  * defining access-control to all OAuth2 client & UI resources: login, logout, authorization callbacks and Swagger-UI

## 3. Project Initialisation
We'll start a spring-boot 3 project from https://start.spring.io/ with those dependencies:
- lombok
- spring-boot-starter-web (used by both REST API and UI servlets)
- spring-boot-starter-webflux (required for WebClient, used to query the API from the UI `@Controller`)
- spring-boot-starter-oauth2-client
- spring-boot-starter-thymeleaf
- spring-boot-starter-actuator

And then add those dependencies:
- [`spring-addons-webmvc-jwt-resource-server`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-webmvc-jwt-resource-server/6.1.1)
- [`spring-addons-webmvc-jwt-client`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-webmvc-client/6.1.1)
- [`springdoc-openapi-starter-webmvc-ui`](https://central.sonatype.com/artifact/org.springdoc/springdoc-openapi-starter-webmvc-ui/2.0.2)
- [`spring-addons-webmvc-jwt-test`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-webmvc-jwt-test/6.1.1)

## 4. Web-Security Configuration

This tutorial uses `spring-addons-webmvc-jwt-resource-server` Spring Boot starter, which auto-configures a default `SecurityFilterChain` for resource-server (REST API), based on properties file. **This resource-server security filter-chain is not explicitly defined in security-conf, but it is there!**.

### 4.1. Resource-Server configuration
As exposed, we rely mostly on auto-configuration to secure REST end-points. The only access-control rules that we have to insert in our Java configuration are those restricting access to actuator (OpenAPI specification is public as per application properties). With `spring-addons-webmvc-jwt-resource-server`, this is done as follow:
```java@Bean
ExpressionInterceptUrlRegistryPostProcessor expressionInterceptUrlRegistryPostProcessor() {
    return (AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry) -> registry
        .requestMatchers(HttpMethod.GET, "/actuator/**").hasAuthority("OBSERVABILITY:read")
        .requestMatchers("/actuator/**").hasAuthority("OBSERVABILITY:write")
        .anyRequest().authenticated();
}
```
Refer to [`resource-server_with_jwtauthenticationtoken`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_jwtauthenticationtoken) for a (much more) verbose alternative using `spring-boot-starter-oauth2-resource-server`.

### 4.2. OAuth2 Client Configuration
In this section, we'll configure:
- an OAuth2 client security filter-chain with access-control to UI resources which are not served by our @Controllers (and for which we can't use method-security)
- authorities mapping from authorization-server user-info end-point (or ID token claims)
- login to authorize our spring OAuth2 client on behalf of an end-user
- logout to terminate user sessions on both our spring OAuth2 client application and the authorization-server

#### 4.2.1. OAuth2 Client Properties
To start with, we'll define a few configuration properties for our client:
- the bas URI for the greeting REST API it consumes
- if the [RP-initiated logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) should be activated (close the session on the OIDC authorization-server when the user logs out)
```java
@Configuration
@ConfigurationProperties
@Data
public class ResourceServerWithUiProperties {
    private URL apiHost;
    private URL uiHost;
    private boolean rpInitiatedLogoutEnabled = true;
}
```
Our client configuration will also use `SpringAddonsOAuth2ClientProperties` to configure non OIDC standard logout handlers.

#### 4.2.2. OAuth2 Security Filter-Chain
Then, we'll add a `SecurityFilterChain` with a `securityMatcher` so that it only applies to the OAuth2 client side of our app, which includes:
- OAuth2 login and callback end-points generated by spring-boot
- logout
- our `@Controller` serving Thymeleaf templates
- static resources
- Swagger-UI
```java
@Order(Ordered.HIGHEST_PRECEDENCE)
@Bean
SecurityFilterChain uiFilterChain(
        HttpSecurity http,
        ServerProperties serverProperties,
        GrantedAuthoritiesMapper authoritiesMapper,
        ResourceServerWithUiProperties appProperties,
        C4LogoutSuccessHandler logoutHandler)
        throws Exception {
    boolean isSsl = serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled();

    http.securityMatcher(new OrRequestMatcher(
        // UiController pages
        new AntPathRequestMatcher("/ui/**"),
        // Swagger pages
        new AntPathRequestMatcher("/swagger-ui/**"),
        // spring-boot-starter-oauth2-client pages
        new AntPathRequestMatcher("/login/**"),
        new AntPathRequestMatcher("/oauth2/**"),
        new AntPathRequestMatcher("/logout/**")));
    
    http.authorizeHttpRequests()
        .requestMatchers("/ui/login", "/login/**", "/oauth2/**", "/logout/**").permitAll()
        .requestMatchers("/swagger-ui.html", "/swagger-ui/**").permitAll()
        .anyRequest().authenticated();
    
    // TODO: Login config
    
    
    // TODO: Logout config

    // If SSL enabled, disable http (https only)
    if (isSsl) {
        http.requiresChannel().anyRequest().requiresSecure();
    }

    return http.build();
}
```
It is worth noting that we intentionally kept some Spring Boot defaults for this filter-chain:
- enabled sessions and CSRF protection
- redirection to login for unauthorized requests to protected resources

#### 4.2.3. Authorities Mapping
As a reminder, clients are focused on ID-token when resource-servers are interested mainly on access-token. But it is very common that claims for user roles are structured the same way in both tokens.

Let's define our own `GrantedAuthoritiesMapper`, using the authorities mapper already auto-configured by `spring-addons-webmvc-jwt-resource-server`:
```java
@Bean
GrantedAuthoritiesMapper userAuthoritiesMapper(Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
    return (authorities) -> {
        Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

        authorities.forEach(authority -> {
            if (authority instanceof OidcUserAuthority oidcAuth) {
                mappedAuthorities.addAll(authoritiesConverter.convert(oidcAuth.getIdToken().getClaims()));

            } else if (authority instanceof OAuth2UserAuthority oauth2Auth) {
                mappedAuthorities.addAll(authoritiesConverter.convert(oauth2Auth.getAttributes()));

            }
        });

        return mappedAuthorities;
    };
}
```

#### 4.2.4. Login Configuration
One of the TODOs we left in the client security filter-chain concerns OAuth2 client authentication on behalf of a user. There are three things we need to configure there:
- use a custom login page served by the UiController
- redirect to an index page accessible only to authenticated users after successful logins
- use our custom authorities mapper
```java
http.oauth2Login()
    .loginPage("%s/ui/login".formatted(appProperties.getUiHost()) )
    .defaultSuccessUrl("%s/ui/index.html".formatted(appProperties.getUiHost()), true)
    .userInfoEndpoint().userAuthoritiesMapper(authoritiesMapper);
```

#### 4.2.5. Logout Configuration
This one is tricky: very few "OIDC" authorization-servers follow the standard when it comes to logout. In the three we use in this tutorial, only Keycloak implements strictly the standard. Neither Auth0 nor Cognito OpenID configuration expose an `end_session_endpoint` and the `logout` end-points they document respectively [here](https://auth0.com/docs/api/authentication#logout) and [there](https://docs.aws.amazon.com/cognito/latest/developerguide/logout-endpoint.html) do not follow the standard. To make things even more complicated, Cognito logout end-point is ot hosted on the same host as the issuer...

Hopefully, [`spring-addons-webmvc-jwt-client`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-webmvc-client/6.1.1) provides with:
- a configurable logout handler for authorization-server implementing "close to [RP-initiated logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) standard", which is the case of both [Auth0](https://auth0.com/docs/api/authentication#logout) and [Cognito](https://docs.aws.amazon.com/cognito/latest/developerguide/logout-endpoint.html
- a composite handler capable of switching between the Spring standard OIDC logout handler and this configurable handler, depending on the authorized client issuer

All we have to do is inject the auto-configured `C4LogoutSuccessHandler
```java
http.logout(
    .logoutRequestMatcher(new AntPathRequestMatcher("/logout")
    .logoutSuccessHandler(logoutHandler)
```

### 4.3. `WebClient` in Servlet ApplicationsAs `WebClient` is auto-configured with reactive configuration. As we use it in a servlet application, we have to bridge from `ClientRegistrationRepository` to `ReactiveClientRegistrationRepository`
```java
@Configuration
public class WebClientConfig {
    @Bean
    WebClient webClient(ClientRegistrationRepository clientRegistrationRepository, OAuth2AuthorizedClientService authorizedClientService) {
        var authorizedClientManager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository, authorizedClientService);
        var oauth = new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
        return WebClient.builder().apply(oauth.oauth2Configuration()).build();
    }
}
```

### 4.4. Multi-Tenant Properties
The last piece of configuration we need is the properties driving all the auto-configuration:
```yaml
api-host: ${scheme}://localhost:${server.port}
ui-host: ${api-host}
rp-initiated-logout-enabled: true

scheme: http
keycloak-port: 8442
keycloak-issuer: ${scheme}://localhost:${keycloak-port}/realms/master
keycloak-confidential-secret: change-me
cognito-issuer: https://cognito-idp.us-west-2.amazonaws.com/us-west-2_RzhmgLwjl
cognito-secret: change-me
auth0-issuer: https://dev-ch4mpy.eu.auth0.com/
autho-secret: change-me

server:
  port: 8080
  ssl:
    enabled: false
      
spring:
  lifecycle:
    timeout-per-shutdown-phase: 30s
  security:
    oauth2:
      client:
        provider:
          keycloak:
            issuer-uri: ${keycloak-issuer}
          cognito:
            issuer-uri: ${cognito-issuer}
          auth0:
            issuer-uri: ${auth0-issuer}
        registration:
          keycloak-public-user:
            authorization-grant-type: authorization_code
            client-id: spring-addons-public
            provider: keycloak
            scope: openid,profile,email,offline_access
          keycloak-programmatic:
            authorization-grant-type: client_credentials
            client-id: spring-addons-confidential
            client-secret: ${keycloak-confidential-secret}
            provider: keycloak
            scope: openid,offline_access
          cognito-confidential-user:
            authorization-grant-type: authorization_code
            client-id: 12olioff63qklfe9nio746es9f
            client-secret: ${cognito-secret}
            provider: cognito
            scope: openid,profile,email
          auth0-confidential-user:
            authorization-grant-type: authorization_code
            client-id: TyY0H7xkRMRe6lDf9F8EiNqCo8PdhICy
            client-secret: ${autho-secret}
            provider: auth0
            scope: openid,profile,email,offline_access

com:
  c4-soft:
    springaddons:
      security:
        cors:
        - path: /api/greet
        issuers:
        - location: ${keycloak-issuer}
          username-claim: $.preferred_username
          authorities:
          - path: $.realm_access.roles
          - path: $.resource_access.*.roles
        - location: ${cognito-issuer}
          username-claim: $.username
          authorities:
          - path: $.cognito:groups
        - location: ${auth0-issuer}
          username-claim: $['https://c4-soft.com/spring-addons']['name']
          authorities:
          - path: $.roles
          - path: $.permissions
        permit-all: 
        - /actuator/health/readiness
        - /actuator/health/liveness
        - /v3/api-docs/**
        - /api/public
        client:
          post-logout-redirect-uri: ${ui-host}/ui
          oauth2-logout:
            - issuer: ${cognito-issuer}
              uri: https://spring-addons.auth.us-west-2.amazoncognito.com/logout
              client-id-argument: client_id
              post-logout-argument: logout_uri
            - issuer: ${auth0-issuer}
              uri: ${auth0-issuer}v2/logout
              client-id-argument: client_id
              post-logout-argument: returnTo
        
logging:
  level:
    org:
      springframework:
        security: DEBUG
            
management:
  endpoint:
    health:
      probes:
        enabled: true
  endpoints:
    web:
      exposure:
        include: '*'
  health:
    livenessstate:
      enabled: true
    readinessstate:
      enabled: true

---
scheme: https
keycloak-port: 8443

server:
  ssl:
    enabled: true

spring:
  config:
    activate:
      on-profile: ssl
```
**Here, we defined 3 authorization-servers for both client and resource-server, and we could define for each how to map username and roles along with how to perform logout on non-standard end-points!**

Don't forget to update the issuer URIs as well as client ID & secrets with your own (or to override it with command line arguments, environment variables or whatever).

## 5. Resource-Server Components
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
We'll need a few resources: static index as well as a few templates with controllers to serve it.

### 6.1. Login Template
The first thing we need is a login page with links to initiate user authentication to each of the registered client with `authorization-code` flow. Here is a `src/main/resources/templates/login.html`:
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">
    <title>Login</title>
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M" crossorigin="anonymous">
    <link href="https://getbootstrap.com/docs/4.0/examples/signin/signin.css" rel="stylesheet" crossorigin="anonymous"/>
</head>
<body>
<div class="container">
    <h2 class="form-signin-heading">Login with OAuth 2.0</h2>
    <table class="table table-striped">
        <tr th:each="client : ${loginOptions}">
            <td><a th:href="@{/oauth2/authorization/{provider}(provider=${client.left})}" th:utext="@{Login with {provider}(provider=${client.right})}">..!..</a></td>
        </tr>
    </table>
</div>
</body>
</html>
```

### 6.2. Greet Template
We also need a `src/main/resources/templates/greet.html` template to display the greeting fetched from the API:
```html
<!DOCTYPE HTML>
<html xmlns:th="http://www.thymeleaf.org">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">
    <title>Greet</title>
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M" crossorigin="anonymous">
    <link href="https://getbootstrap.com/docs/4.0/examples/signin/signin.css" rel="stylesheet" crossorigin="anonymous"/>
</head>

<body>
<div class="container">
    <h1 class="form-signin-heading">Greeting from the REST API</h1>
    <div th:utext="${msg}">..!..</div>
    <table class="table table-striped">
        <tr><td><a href="/ui/index.html">Back to index</a></td></tr>
    </table>
</div>
</body>
```

### 6.3. Static Index Page
To finish with pages, we'll define a `src/main/resources/static/ui/index.html` page for authenticated users to choose between the greeting and the Swagger UI:
```html
<!DOCTYPE HTML>
<html>

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">
    <title>Multi-tenant UI</title>
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M" crossorigin="anonymous">
    <link href="https://getbootstrap.com/docs/4.0/examples/signin/signin.css" rel="stylesheet" crossorigin="anonymous"/>
</head>

<body>
<div class="container">
    <h1 class="form-signin-heading">Spring-addons OAuth2 tutorial with resource-server and multi-tenant Thymeleaf client</h1>
    <table class="table table-striped">
        <tr><td><a href="/ui/greet">Go to Thymeleaf UI</a></td></tr>
        <tr><td><a href="/swagger-ui/index.html">Go to Swagger UI</a></td></tr>
        <tr><td><a href="/logout">Logout</a></td></tr>
    </table>
</div>
</body>
```

### 6.4. UI Controllers
And now, here is the controller for the two templates above:
```java
@Controller
@RequestMapping("/ui")
@RequiredArgsConstructor
public class UiController {
    private final WebClient api;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final ResourceServerWithUiProperties props;
    private final OAuth2ClientProperties clientProps;

    @GetMapping("/login")
    public String getLogin(Model model) throws URISyntaxException {
        final var loginOptions = clientProps.getRegistration().entrySet().stream()
                .filter(e -> "authorization_code".equals(e.getValue().getAuthorizationGrantType()))
                .map(e -> Pair.of(e.getKey(), e.getValue().getProvider()))
                .toList();
        
        model.addAttribute("loginOptions", loginOptions);
        
        return "login";
    }

    @GetMapping("/greet")
    public String getGreeting(Model model, OAuth2AuthenticationToken auth) throws URISyntaxException {
        try {
            final var authorizedClient = authorizedClientService.loadAuthorizedClient(auth.getAuthorizedClientRegistrationId(), auth.getName());
            final var greetApiUri = new URI(props.getApiHost().getProtocol(), props.getApiHost().getAuthority(), "/api/greet", null, null);
            final var response =
                    api.get().uri(greetApiUri).attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
                            .exchangeToMono(r -> r.toEntity(String.class)).block();
            model.addAttribute("msg", response.getStatusCode().is2xxSuccessful() ? response.getBody() : response.getStatusCode().toString());

        } catch (RestClientException e) {
            final var error = e.getMessage();
            model.addAttribute("msg", error);

        }
        return "greet";
    }
}
```
The `login` method retrieves OAuth2 client registrations with authorization-code and builds a model out of it so that the template can iterate to propose login options to the user.

The `greet` method configures `WebClient` to use curent user access-token to fetch a greeting from the API.

To provide with decent user experience, we'll also add a controller to redirect from `/` to `/ui`:
```java
@Controller
@RequestMapping("/")
@RequiredArgsConstructor
public class IndexController {
    @GetMapping("/")
    public RedirectView getIndex() throws URISyntaxException {
        return new RedirectView("/ui");
    }
}
```

## 7. Conclusion
In this tutorial we saw how to configure different security filter-chains and select to which routes each applies. We set-up
- an OAuth2 client filter-chain with login, logout and sessions (and CSRF protection) for UI
- a state-less (neither session nor CSRF protection) filter-chain for the REST API.

We also saw how handy `spring-addons-webmvc-jwt-resource-server` and `spring-addons-webmvc-jwt-client` when it comes to configuring a resource-server or client logout.
