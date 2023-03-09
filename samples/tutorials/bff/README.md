# Implementing the **B**ackend **F**or **F**rontend pattern
In this tuturial, we will implement a n-tier application involving a "rich" front-end running in a browser, a gateway configured as  BFF, and a REST API configured as an OAuth2 resource server.

## 1. Overview
For that, we will use:
- `spring-cloud-gateway` as BFF (OAuth2 client with login, logout and `TokenRelay` filter)
- a Spring servlet API as OAuth2 resource-server
- Angular as browser application framework
- Keycloak, Cognito and Auth0 as authorization servers

## 2. The **B**ackend **F**or **F**rontend Pattern
BFF aims at hiding the OAuth2 tokens from the browser. In this pattern, rich applications (Angular, React, Vue, etc.) are secured with sessions on a middle-ware, the BFF, which is the only OAuth2 client and replaces session cookie with an access-token before forwarding a request from the browser to the resource-server.

There is a big trend toward this pattern because it is considered more secure as access-tokens are :
- kept on the server instead of being exposed to the browser (and frequently to Javascript code)
- delivered to OAuth2 confidential clients (browser apps can't keep a secret and are "public" clients), which reduces the risk that tokens are delivered to programs pretending to be the client we expect

Keep in mind that sessions are a common attack vector and that this two conditions must be met:
- CSRF protection must be enabled on the BFF (because browser app security relies on sessions)
- session cookie must be `Secured` (exchanged over https only) and `HttpOnly` (hidden to Javascript code) and should be flagged with `SameSite`

When user authentication is needed:
0. the browser app redirects the user to a BFF endpoint dedicated to authorization-code initiation
1. the BFF redirects the user to the authorization-server (specifying a callback URL where it expects to receive an authorization code in return)
2. the user authenticates
3. the authorization-server redirects the user back to the BFF with an authorization code
4. the BFF fetches OAuth2 tokens from the authorization-server and stores it in session
5. the BFF redirects the user back to the browser app at an URI specified at step 0.

## 3. `spring-cloud-gateway` as BFF
In theory, Spring cloud gateway is easy to configure as a BFF:
- make it an OAuth2 **client**
- activate the `TokenRelay` filter
- serve both the API and the UI through it

But when it comes to providing with a multi-tenant OAuth2 client with login, logout, CSRF protection correctly configured, token relay and CORS headers correctly handled, things can get complicated to tie together, reason for creating this tutorial.

### 3.1. Authorization-Server Prerequisites
A client should be declared for the BFF on each authorization-server we wish to accept as identity provider. As this client will run on a server we trust, it should be "confidential" (clients running in a browser can't keep a secret and have to be "public"). This adds to security as it reduces risk that tokens are emitted for a malicious client (but a firewall restricting authorization-server `token` endpoint access to BFF server would be nice too).

For this tutorial, we'll assume that confidential clients are available for Keycloak, Auth0 and Cognito. Remind to pick `client-id` and `client-secret`, we'll need it to configure the BFF. 

As we intend to authenticate users, next thing to check is that authorization-code flow is activated for our clients.

We'll also need the following configuration on each identity provider:
- `http://localhost:7443/login/oauth2/code/{registrationId}` is set as authorized post-login URI (where `registrationId` is the key in for the "registration" used by that client in the YAML / properties file)
- `http://localhost:7443/ui` is set as authorized post logout URI

Last, the BFF (`http://localhost:7443`) must also be configured as allowed origin.

Note that you might (should?) activate the `ssl` profile when running the projects. If so, replace the `http` scheme with `https` when setting the conf on identity providers (or allow both http and https URLs). If you d'ont have SSL certificates yet, you might have a look at [this repo](https://github.com/ch4mpy/self-signed-certificate-generation).

### 3.2. Keycloak Configuration Details
You might skip this section if you are using another OIDC authorization-server (instead, refer to your provider documentation to implement the prerequisites listed above). 

You could also repeat this secttion in a second realm to implement multi-tenancy with a single Keycloak server (instead of creating accounts on Auth0, Cognito or whatever).

In administration console, got to `clients`
- create a new client with `spring-addons-confidential` as `Client ID` and click `Next`
- enable `Client authentication`, disable `Direct access grants`, enable `Service accounts roles` and click `Save`
- secret is then accessible from `credentials` tab
- got to `Settings` tab and set:
  * `http://localhost:7443/*` and `https://localhost:7443/*` as `Valid redirect URIs`
  * `+` as `Valid post logout redirect URIs`
  * `+` as `Web origins`
- save

### 3.3. The BFF
As mentioned earlier, we'll use `spring-cloud-gateway` configured as an OAuth2 client with login and logout.

To make core BFF concepts and configuration simpler to grasp, the user will be limited to having a single identity at a time: he'll be able to choose from several identity providers, but will have to logout before he can login with another one. For the details of what it implies to allow a user have several identities at the same time (and how to implement sequential redirections to each identity provider when loging out), refer to the "Resource Server & UI" tutorial.

#### 3.3.1. Project Initialization
From [https://start.spring.io](https://start.spring.io) download a new project with:
- `spring-cloud-starter-gateway` 
- `spring-boot-starter-oauth2-client`
- `spring-boot-starter-actuator`
- `lombok`

We'll then add the following dependencies:
- [`spring-addons-webflux-client`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-webflux-client/6.1.2) to have a few useful bean autoconfigured:
  * CORS configuration from properties
  * `LogoutSuccessHandler` for "almost" OIDC complient providers
  * authorization request resolver with a base path configurable from properties (avoid problems due to bad hostname or port inference for redirections)
  * authorities mapper configurable per issuer (and source claim)
- [`swagger-annotations-jakarta`](https://central.sonatype.com/artifact/io.swagger.core.v3/swagger-annotations-jakarta/2.2.8) for a cleaner OpenAPI specification (if the maven `openapi` profile, which is omitted in the tutorial but included in the source, is activted)

#### 3.3.2 Application Properties
Configure application properties with
- OAuth2 client
- TokenRelay
- two routes (one for the resource-server and the other for the browser app)

As mentioned above, we use `spring-addons-webflux-client` which requires a little extra configuration from properties
```yaml
scheme: http
keycloak-port: 8442
keycloak-issuer: ${scheme}://localhost:${keycloak-port}/realms/master
keycloak-secret: change-me
cognito-issuer: https://cognito-idp.us-west-2.amazonaws.com/us-west-2_RzhmgLwjl
cognito-secret: change-me
auth0-issuer: https://dev-ch4mpy.eu.auth0.com/
autho-secret: change-me

gateway-uri: ${scheme}://localhost:${server.port}
greetings-api-uri: ${scheme}://localhost:6443/greetings
angular-uri: ${scheme}://localhost:4200

server:
  port: 7443
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
          keycloak-confidential-user:
            authorization-grant-type: authorization_code
            client-name: Keycloak
            client-id: spring-addons-confidential
            client-secret: ${keycloak-secret}
            provider: keycloak
            scope: openid,profile,email,offline_access,roles
          cognito-confidential-user:
            authorization-grant-type: authorization_code
            client-name: Cognito
            client-id: 12olioff63qklfe9nio746es9f
            client-secret: ${cognito-secret}
            provider: cognito
            scope: openid,profile,email
          auth0-confidential-user:
            authorization-grant-type: authorization_code
            client-name: Auth0
            client-id: TyY0H7xkRMRe6lDf9F8EiNqCo8PdhICy
            client-secret: ${autho-secret}
            provider: auth0
            scope: openid,profile,email,offline_access
  cloud:
    gateway:
      default-filters:
      - TokenRelay=
      - DedupeResponseHeader=Access-Control-Allow-Credentials Access-Control-Allow-Origin
      - SaveSession
      - SecureHeaders
      routes:
      - id: greetings
        uri: ${greetings-api-uri}
        predicates:
        - Path=/greetings/**
      - id: ui
        uri: ${angular-uri}
        predicates:
        - Path=/ui/**
      - id: home
        uri: ${angular-uri}
        predicates:
        - Path=/
        filters:
        - RewritePath=/,/ui

com:
  c4-soft:
    springaddons:
      security:
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
        - "/login-options"
        - "/me"
        - "/actuator/health/readiness"
        - "/actuator/health/liveness"
        - "/v3/api-docs/**"
        client:
          client-uri: ${gateway-uri}
          post-logout-redirect-path: /ui
          oauth2-logout:
            - client-registration-id: cognito-confidential-user
              uri: https://spring-addons.auth.us-west-2.amazoncognito.com/logout
              client-id-request-param: client_id
              post-logout-uri-request-param: logout_uri
            - client-registration-id: auth0-confidential-user
              uri: ${auth0-issuer}v2/logout
              client-id-request-param: client_id
              post-logout-uri-request-param: returnTo
            
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

logging:
  level:
    root: ERROR
    org.springframework.security: DEBUG
    
---
spring:
  config:
    activate:
      on-profile: ssl

server:
  ssl:
    enabled: true

scheme: https
keycloak-port: 8443
```

You might also consider defining `SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_{registrationId}_CLIENT_SECRET` environment variables instead of putting the secrets in your properties file.

#### 3.3.3. Web Security Configuration
For the CSRF token to be exposed to our Angular application as well as some access control and login / logout customisation, we'll have to define our own `SecurityWebFilterChain`:
```java
@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class WebSecurityConfig {
    @Order(Ordered.HIGHEST_PRECEDENCE)
    @Bean
    SecurityWebFilterChain clientFilterChain(
            ServerHttpSecurity http,
            ServerProperties serverProperties,
            ReactiveClientRegistrationRepository clientRegistrationRepository,
            @Value("${gateway-uri}") URI gatewayUri,
            ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver,
            SpringAddonsSecurityProperties addonsProperties,
            CorsConfigurationSource corsConfigurationSource)
            throws Exception {
        // @formatter:off
        // securityMatcher is restricted to UI resources and we want all to be accessible to anonymous
        http.authorizeExchange().pathMatchers("/", "/login/**", "/login-options", "/oauth2/**", "/ui/**", "/v3/api-docs/**").permitAll()
            .anyExchange().authenticated();

        http.exceptionHandling(exceptionHandling -> exceptionHandling
                // redirect unauthorized request to the Angular UI which exposes a public landing page and identity provider selection
                .authenticationEntryPoint(new RedirectServerAuthenticationEntryPoint("/ui")))
            .oauth2Login(oauth2 -> oauth2
                // override the default authorization request resolver with one using properties for the BFF scheme, hostname and port
                .authorizationRequestResolver(authorizationRequestResolver));

        // If SSL enabled, disable http (https only)
        if (Optional.ofNullable(serverProperties.getSsl()).map(Ssl::isEnabled).orElse(false)) {
            http.redirectToHttps();
        }

        // configure CORS from application properties
        http.cors().configurationSource(corsConfigurationSource);

        http.csrf(csrf -> csrf
          // expose CSRF token to Javascript applications
          .csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse())
          // Could not get CSRF work with Angular and new XorServerCsrfTokenRequestAttributeHandler (yet?)
          // For now, hope that SameSite in CsrfCookieWebFilter below is enough and disable BREACH protection
          // as per https://docs.spring.io/spring-security/reference/reactive/exploits/csrf.html#webflux-csrf-configure-request-handler
          .csrfTokenRequestHandler(new ServerCsrfTokenRequestAttributeHandler()));
        // @formatter:on

        return http.build();
    }

    @Component
    @Configuration
    public class CsrfCookieWebFilter implements WebFilter {

        @Override
        public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
            String key = CsrfToken.class.getName();
            Mono<CsrfToken> csrfToken = null != exchange.getAttribute(key) ? exchange.getAttribute(key) : Mono.empty();
            return csrfToken.doOnError(e -> {
                exchange.getResponse().getCookies().remove("XSRF-TOKEN");
            }).doOnSuccess(token -> {
                if (token == null) {
                    exchange.getResponse().getCookies().remove("XSRF-TOKEN");
                } else {
                    ResponseCookie cookie = ResponseCookie.from("XSRF-TOKEN", token.getToken()).maxAge(Duration.ofHours(1)).httpOnly(false).path("/")
                            .sameSite(Cookie.SameSite.LAX.attributeValue()).build();
                    exchange.getResponse().getCookies().add("XSRF-TOKEN", cookie);
                }
            }).then(chain.filter(exchange));
        }
    }
}
```
Note that a few beans used here come from `SpringAddonsOAuth2ClientBeans` in `spring-addons-webflux-client`. Refer to its Javadoc or source for auto-configuration details details.

#### 3.3.4. Gateway Controller
There are a endpoints that we will expose from the gateway itself:
- `/login-options` to get a list of available options to initiate an authorization-code flow
- `/me` to get some info about the current user, retrieved from the **ID token** (if the user is authenticated, an empty "anonymous" user is returned otherwise)
- `/logout` to invalidate current user session and get the URI of the request to terminate the session on the identity provider
```java
@Controller
@Tag(name = "Gateway")
public class GatewayApiController {
    private final ReactiveOAuth2AuthorizedClientService authorizedClientService;
    private final SpringAddonsOAuth2ClientProperties addonsClientProps;
    private final LogoutRequestUriBuilder logoutRequestUriBuilder;
    private final List<LoginOptionDto> loginOptions;

    public GatewayApiController(
            OAuth2ClientProperties clientProps,
            ReactiveOAuth2AuthorizedClientService authorizedClientService,
            SpringAddonsOAuth2ClientProperties addonsClientProps,
            LogoutRequestUriBuilder logoutRequestUriBuilder) {
        this.authorizedClientService = authorizedClientService;
        this.addonsClientProps = addonsClientProps;
        this.logoutRequestUriBuilder = logoutRequestUriBuilder;
        this.loginOptions = clientProps.getRegistration().entrySet().stream().filter(e -> "authorization_code".equals(e.getValue().getAuthorizationGrantType()))
                .map(e -> new LoginOptionDto(e.getValue().getProvider(), "%s/oauth2/authorization/%s".formatted(addonsClientProps.getClientUri(), e.getKey())))
                .toList();
    }

    @GetMapping(path = "/login-options", produces = "application/json")
    @ResponseBody
    @Tag(name = "getLoginOptions")
    public Mono<List<LoginOptionDto>> getLoginOptions(Authentication auth) throws URISyntaxException {
        final boolean isAuthenticated = auth instanceof OAuth2AuthenticationToken;
        return Mono.just(isAuthenticated ? List.of() : this.loginOptions);
    }

    @GetMapping(path = "/me", produces = "application/json")
    @ResponseBody
    @Tag(name = "getMe")
    @Operation(responses = { @ApiResponse(responseCode = "200") })
    public Mono<UserDto> getMe(Authentication auth) {
        if (auth instanceof OAuth2AuthenticationToken oauth && oauth.getPrincipal() instanceof OidcUser user) {
            final var claims = new OpenidClaimSet(user.getClaims());
            return Mono.just(
                    new UserDto(
                            claims.getSubject(),
                            Optional.ofNullable(claims.getIssuer()).map(URL::toString).orElse(""),
                            oauth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList()));
        }
        return Mono.just(UserDto.ANONYMOUS);
    }

    @PutMapping(path = "/logout")
    @Tag(name = "logout")
    @ResponseBody
    @Operation(parameters = {}, responses = { @ApiResponse(responseCode = "202"), @ApiResponse(responseCode = "401") })
    public Mono<ResponseEntity<Void>> logout(@Parameter(hidden = true) OAuth2AuthenticationToken auth, @Parameter(hidden = true) WebSession session) {
        final var user = (OidcUser) auth.getPrincipal();
        return authorizedClientService.loadAuthorizedClient(auth.getAuthorizedClientRegistrationId(), user.getSubject()).map(authorizedClient -> {
            final var postLogoutUri =
                    UriComponentsBuilder.fromUri(addonsClientProps.getClientUri()).path("/ui").encode(StandardCharsets.UTF_8).build().toUriString();
            String logoutUri = logoutRequestUriBuilder.getLogoutRequestUri(authorizedClient, user.getIdToken().getTokenValue(), URI.create(postLogoutUri));

            this.authorizedClientService.removeAuthorizedClient(auth.getAuthorizedClientRegistrationId(), user.getSubject());
            session.invalidate();
            return ResponseEntity.accepted().location(URI.create(logoutUri)).build();
        });
    }

    @Data
    @AllArgsConstructor
    static class UserDto implements Serializable {
        private static final long serialVersionUID = 7279086703249177904L;
        static final UserDto ANONYMOUS = new UserDto("", "", List.of());

        @NotEmpty
        private final String subject;

        private final String issuer;

        private final List<String> roles;
    }

    @Data
    @AllArgsConstructor
    static class LoginOptionDto implements Serializable {
        private static final long serialVersionUID = -60479618490275339L;

        @NotEmpty
        private final String label;

        @NotEmpty
        private final String loginUri;
    }
}
```

## 4. Resource-Server
We will use `com.c4-soft.springaddons:spring-addons-webmvc-jwt-resource-server:6.1.2`, a thin wrapper arround `spring-boot-starter-oauth2-resource-server`.

This resource-server will expose a single `/greetings` endpoint returning a message with user data retrieved from the **access token** (as oposed to the "client" `/me` endpoint which uses data from the ID token)

### 4.1. Project Initialization
From [https://start.spring.io](https://start.spring.io) download a new project with:
- `spring-boot-starter-actuator`
- `spring-boot-starter-web`

and then add this dependencies:
- [`spring-addons-webmvc-jwt-resource-server`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-webmvc-jwt-resource-server/6.1.2)
- [`spring-addons-webmvc-test`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-webmvc-test/6.1.2)
- [`swagger-annotations-jakarta`](https://central.sonatype.com/artifact/io.swagger.core.v3/swagger-annotations-jakarta/2.2.8) for a cleaner OpenAPI specification (if the maven `openapi` profile, which is omitted in the tutorial but included in the source, is activted)

### 4.2. Web Security Customization
Then add this bean to your boot application to switch successful authorizations from the default `JwtAuthenticationToken` to `OAuthentication<OpenidClaimSet>`:
```java
@Configuration
@EnableMethodSecurity
static class WebSecurityConfig {
  @Bean
  OAuth2AuthenticationFactory authenticationFactory(
      Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
      SpringAddonsSecurityProperties addonsProperties) {
    return (bearerString, claims) -> new OAuthentication<>(
        new OpenidClaimSet(claims, addonsProperties.getIssuerProperties(claims.get(JwtClaimNames.ISS)).getUsernameClaim()),
        authoritiesConverter.convert(claims),
        bearerString);
  }
}
```
With quite some auto-configuration by `AddonsWebSecurityBeans` from `spring-addons-webmvc-jwt-resource-server`, using this properties:
```yaml
scheme: http
origins:  ${scheme}://localhost:7443
keycloak-port: 8442
keycloak-issuer: ${scheme}://localhost:${keycloak-port}/realms/master
cognito-issuer: https://cognito-idp.us-west-2.amazonaws.com/us-west-2_RzhmgLwjl
auth0-issuer: https://dev-ch4mpy.eu.auth0.com/

server:
  port: 6443
  error:
    include-message: always
  ssl:
    enabled: false

spring:
  lifecycle:
    timeout-per-shutdown-phase: 30s

com:
  c4-soft:
    springaddons:
      security:
        cors:
        - path: /**
          allowed-origins: ${origins}
        issuers:
        - location: ${keycloak-issuer}
          username-claim: preferred_username
          authorities:
          - path: $.realm_access.roles
          - path: $.resource_access.*.roles
        - location: ${cognito-issuer}
          username-claim: username
          authorities:
          - path: cognito:groups
        - location: ${auth0-issuer}
          username-claim: $['https://c4-soft.com/spring-addons']['name']
          authorities:
          - path: roles
          - path: permissions
        permit-all: 
        - "/actuator/health/readiness"
        - "/actuator/health/liveness"
        - "/v3/api-docs/**"
        
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

### 4.3. REST Controller
Here is the @Controller we will be using:
```java
@RestController
@RequestMapping(path = "/greetings", produces = MediaType.APPLICATION_JSON_VALUE)
@Tag(name = "Greetings")
public class GreetingsController {
    @GetMapping()
    @Tag(name = "get")
    public GreetingDto getGreeting(OAuthentication<OpenidClaimSet> auth) {
        return new GreetingDto(
                "Hi %s! You are authenticated by %s and granted with: %s.".formatted(auth.getName(), auth.getAttributes().getIssuer(), auth.getAuthorities()));
    }

    @Data
    @AllArgsConstructor
    @Builder
    public static class GreetingDto implements Serializable {
        private static final long serialVersionUID = -5404506920234624316L;

        private String message;
    }
}
```

## 5. Browser client
The details of creating an Angular workspace with an application and two client libraries generated from OpenAPI specifications (itself generated by a maven plugin in our Spring projects) goes beyond the aim of this tutorial.

Make sure you run `npm i` before you `ng serve` the application. This will pull all the necessary dependencies and also generate the client libraries for the Gateway and Greeting APIs (which are documented with OpenAPI).

The important things to note here are:
- we expose a public landing page (accessible to anonymous users)
- the Angular app queries the gateway for the login options it proposes and then renders a page for the user to choose one
- due to security reasons, login and logout redirections are made by setting `window.location.href` (see `UserService`) implementation
- still for security reasons, the logout is a `PUT`. It invalidates the user session on the BFF and returns, in a `location` header, an URI for a `GET` request to invalidate the session on the authorization server (identity provider). It's ok for the second request to be a get becasue it should contain the ID token associated with the session to invalidate (which acts like a CSRF token in this case).
