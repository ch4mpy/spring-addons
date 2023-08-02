# Implementing the **B**ackend **F**or **F**rontend pattern with `spring-cloud-gateway`
In this tutorial, we will implement a n-tier application involving:
- a "rich" JS front-end running in a browser (Angular)
- `spring-cloud-gateway` configured as  BFF
- a Spring Boot 3 servlet REST API configured as an OAuth2 resource server
- Keycloak, Cognito and Auth0 as authorization servers
- two different ways to query the `greetings` API:
  * requests at `/bff/greetings-api/v1/greeting` authorized with a session cookie. This is the BFF pattern and what the Angular app uses.
  * requests at `/resource-server/greetings-api/v1/greeting` authorized with an access token. This is what Postman or any other OAuth2 client would use.

The latest SNAPSHOT is deployed by CI / CD to a publicly available K8s cluster managed by [OVH](https://www.ovhcloud.com/fr/public-cloud/kubernetes/)): [https://bff.demo.c4-soft.com/ui/](https://bff.demo.c4-soft.com/ui/)

## 0. Disclaimer
There are quite a few samples, and all are part of CI to ensure that source compile and all tests pass. Unfortunately, this README is not automatically updated when source changes. Please use it as a guidance to understand the source. **If you copy some code, be sure to do it from the source, not from this README**.

## 1. Prerequisites
We assume that [tutorials main README prerequisites section](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials#prerequisites) has been achieved and that you have a minimum of 1 OIDC Provider (2 would be better) with ID and secret for clients configured with authorization-code flow.

Also, we will be using `spring-addons-starter-oidc`. If for whatever reason you don't want to do so, **you won't benefit of the back-channel logout implementation and you'll have quite some tricky java configuration to write**. Here are some resources useful to write security conf without `spring-addons-starter-oidc`:
- the [`reactive-client` tutorial](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/reactive-client) to configure `spring-cloud-gateway` as an OAuth2 client with login and logout (you can skip the authorities mapping section which is not needed here). .
- the [`reactive-resource-server` tutorial](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/reactive-resource-server) along with the [`resource-server_with_ui`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_ui) as this tutorial is using both a client security filter-chain (with sessions and oauth2Login) for resources matched by `com.c4-soft.springaddons.oidc.client.security-matchers` and a resource server filter-chain as default for resources not needing a session.
- the [`servlet-resource-server` tutorial](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/servlet-resource-server) to configure the REST API as an OAuth2 resource server secured with JWTs

To make core BFF concepts and configuration simpler to grasp, the user will be limited to having a single identity at a time: he'll be able to choose from several identity providers, but will have to logout before he can login with another one (same configuration as in the [`reactive-client` tutorial](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/reactive-client)). For the details of what it requires to allow a user to have several identities at the same time (and how to implement sequential redirections to each identity provider when logging out), refer to the [Resource Server & UI](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_ui) tutorial.

## 2. `spring-cloud-gateway` as BFF
In theory, Spring cloud gateway is easy to configure as a BFF:
- make it an OAuth2 **client**
- activate the `TokenRelay=` filter
- serve both the API and the UI through it

But when it comes to providing with a multi-tenant OAuth2 client with login, logout, CSRF protection with cookies readable by JS applications, token relay and CORS headers correctly handled, things can get complicated to tie together.

### 2.1. The **B**ackend **F**or **F**rontend Pattern
BFF aims at hiding the OAuth2 tokens from the browser. In this pattern, rich applications (Angular, React, Vue, etc.) are secured with sessions on a middle-ware, the BFF, which is the only OAuth2 client and replaces session cookie with an access token before forwarding a request from the browser to the resource server.

There is a big trend toward this pattern because it is considered safer than JS applications configured as OAuth2 public clients as access tokens are:
- kept on the server instead of being exposed to the browser (and Javascript code)
- delivered to OAuth2 confidential clients (browser apps can't keep a secret and are "public" clients), which reduces the risk that tokens are delivered to programs pretending to be the client we expect

Keep in mind that sessions are a common attack vector and that this two conditions must be met:
- CSRF and BREACH protections must be enabled on the BFF (because browser app security relies on sessions)
- session cookie must be `Secured` (exchanged over https only) and `HttpOnly` (hidden to Javascript code). It being flagged with `SameSite` would be nice.

When user authentication is needed:

0. the browser app redirects the user to a BFF endpoint dedicated to authorization-code initiation
1. the BFF redirects the user to the authorization-server (specifying a callback URL where it expects to receive an authorization code in return)
2. the user authenticates
3. the authorization-server redirects the user back to the BFF with an authorization code
4. the BFF fetches OAuth2 tokens from the authorization-server and stores it in session
5. the BFF redirects the user back to the browser app at an URI specified at step 0.

### 2.2. Quick Note On CORS
When serving both the UI (Angular app) and the REST API(s) through the gateway, from the browser perspective, all requests have the same origin, which removes the need for any CORS configuration. This is the setup we'll adopt here. If you prefer to access the Angular app directly (http://localhost:4200/ui by default on your dev environment) instead of through the gateway (http://localhost:8080/ui by default on your dev environment), then you'll have to configure CORS on the resource server to allow requests from the Angular host (http://localhost:4200).

### 2.3. Project Initialization
From [https://start.spring.io](https://start.spring.io) download a new project with:
- Gateway
- OAuth2 client
- OAuth2 resource server
- Spring Boot Actuator
- Lombok

Then, we'll add the a dependency to [`spring-addons-starter-oidc`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-starter-oidc) to create for us:
- an OAuth2 client `SecurityWebFilterChain` which intercepts all requests matched by `com.c4-soft.springaddons.oidc.client.security-matchers`
- a logout success handler configured from properties for "almost" OIDC complient providers (Auth0 and Cognito do not implement standrad RP-Initiated Logout)
- a client side implementation for Back-Channel Logout
- a few other features not important in this tutorial (multi-tenancy, as well as authorities mapping and CORS configuration from properties)
- an OAuth2 resource server `SecurityWebFilterChain` to process all the requests that were not matched in filter-chains with lower order.
```xml
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starter-oidc</artifactId>
    <version>${spring-addons.version}</version>
</dependency>
```

### 2.4. Application Properties
Let's first detail the configuration properties used to configure `spring-cloud-gateway`.

The first part defines some constants to be reused later on and, for some of it, be overridden in profiles. You might also consider defining `KEYCLOAK_SECRET`, `AUTH0_SECRET` and `COGNITO_SECRET` environment variables instead of editing the secrets in the following:
```yaml
scheme: http
keycloak-port: 8442
keycloak-issuer: ${scheme}://localhost:${keycloak-port}/realms/master
keycloak-client-id: spring-addons-confidential
keycloak-secret: change-me
cognito-issuer: https://cognito-idp.us-west-2.amazonaws.com/us-west-2_RzhmgLwjl
cognito-client-id: change-me
cognito-secret: change-me
auth0-issuer: https://dev-ch4mpy.eu.auth0.com/
auth0-client-id: change-me
auth0-secret: change-me

gateway-uri: ${scheme}://localhost:${server.port}
greetings-api-uri: ${scheme}://localhost:6443/greetings
angular-uri: ${scheme}://localhost:4200
```
Then comes some standard Spring Boot web application configuration:
```yaml
server:
  port: 8080
  ssl:
    enabled: false

spring:
  lifecycle:
    timeout-per-shutdown-phase: 30s
```
And after that the OAuth2 configuration for an OAuth2 client allowing to users to authenticate (`authorization_code`) from 3 different OIDC Providers
```yaml
spring
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
            client-id: ${keycloak-client-id}
            client-secret: ${keycloak-secret}
            provider: keycloak
            scope: openid,profile,email,offline_access,roles
          cognito-confidential-user:
            authorization-grant-type: authorization_code
            client-name: Cognito
            client-id: ${cognito-client-id}
            client-secret: ${cognito-secret}
            provider: cognito
            scope: openid,profile,email
          auth0-confidential-user:
            authorization-grant-type: authorization_code
            client-name: Auth0
            client-id: ${auth0-client-id}
            client-secret: ${auth0-secret}
            provider: auth0
            scope: openid,profile,email,offline_access
```
Next, comes the Gateway configuration itself with:
- default filters (applying to all routes):
  * `SaveSession` to ensure that OAuth2 tokens are saved (in session) between requests
  * `DedupeResponseHeader` preventing potentially duplicated CORS headers
- a few routes:
  * `home` is redirecting gateway index to UI one
  * `/bff/greetings-api/v1/**` is forwarding requests to our resource server (`greetings` REST API) according to the BFF pattern (for front-ends secured with sessions):
    - `TokenRelay` filter is applied to replace session cookies with OAuth2 access tokens
    - `StripPrefix` filter removes the first 3 segments of request path (`/bff/greetings-api/v1/greeting/**` will be routed to greetings-api as `/greeting/**`)
  * `/resource-server/greetings-api/v1/**` is forwarding requests to our resource server (`greetings` REST API) for OAuth2 clients (requests should be authorized with an OAuth2 access token already, so no `TokenRelay filter`)
  * `ui` is forwarding to the Angular app (angular dev server with current localhost conf)
  * `letsencrypt` is needed only when deploying to Kubernetes to route HTTP-01 challenge request when requesting a valid SSL certificate
```yaml
  cloud:
    gateway:
      default-filters:
      - DedupeResponseHeader=Access-Control-Allow-Credentials Access-Control-Allow-Origin
      - SaveSession
      routes:
      # set a redirection from / to the UI
      - id: home
        uri: ${gateway-uri}
        predicates:
        - Path=/
        filters:
        - RedirectTo=301,${gateway-uri}/ui/
      # BFF access to greetings API (with TokenRelay replacing session cookies with access tokens)
      # To be used by SPAs (Angular app in our case)
      - id: greetings-api-bff
        uri: ${greetings-api-uri}
        predicates:
        - Path=/bff/greetings-api/v1/**
        filters:
        - TokenRelay=
        - StripPrefix=3
      # direct access to greetings API (without the TokenRelay => requests should be authorized with an access tokens already)
      # To be used by OAuth2 clients like Postman or mobile apps configured as OAuth2 (public) clients
      - id: greetings-api-oauth2-clients
        uri: ${greetings-api-uri}
        predicates:
        - Path=/resource-server/greetings-api/v1/**
        filters:
        - StripPrefix=3
      # access to UI resources (Angular app in our case)
      - id: ui
        uri: ${ui-uri}
        predicates:
        - Path=/ui/**
      # used by the cert manager on K8s
      - id: letsencrypt
        uri: https://cert-manager-webhook
        predicates:
        - Path=/.well-known/acme-challenge/**
```

Then comes `spring-addons-starter-oidc` configuration:
- `ops` properties for each of the OIDC Providers we trust (issuer URI, authorities mapping and claim to use as username)
- two security filter chains:
  * a "client" one for resources secured with a session. It contains a security matcher to define which requests it should process, as well as configuration for login and logout
  * a "resource server" with lowest precedence which will process all requests not intercepted by the client filter-chain.
- `client-uri` is used to work with absolute URIs in login process
- `security-matchers` is an array of path matchers for routes processed by the auto-configured client security filter-chain. If it was left null or empty, client auto-configuration would be turned off.
- `permit-all` is a list of path matchers for resources accessible to all requests, even unauthorized ones (end-points not listed here like `/logout` will be accessible only to authenticated users)
  * `/login/**` and `/oauth2/**` are used by Spring during the authorizatoin-code flow
  * `/` and `/ui/**` are there so that unauthorized users can display the Angular app containing a landing page and login buttons
  * `/login-options` and `/me` are end-points on the gateway itself exposing the different URIs to initiate an authorization-code flow (one per client registration above) and current user OpenID claims (empty if unauthorized, which is convenient to display user status in the Angular app)
  * `/v3/api-docs/**` gives a public access to Gateway OpenAPI specification for its `/login-options` and `/me` end-points
- `csrf` with `cookie-accessible-from-js` requires that CSRF tokens are sent in an `XSRF-TOKEN` cookie with `http-enabled=false` so that Angular application can read it and send requests with this token in X`-XSRF-TOKEN` header. It also adds a `WebFilter` for the cookie to be actually added to responses and configures a CSRF handler protecting against BREACH attacks.
- `login-path`, `post-login-redirect-path` and `post-logout-redirect-path` are pretty straight forward. this are relative path to the `client-uri` configured earlier
- `back-channel-logout-enabled` when set to `true`, a `/backchannel-logout` end-point is added, listening for POST requests from the OIDC Providers when a user logs out from another application the current client (useful in SSO environments). This endpoint is secured by a dedicated filter-chain matching only `/backchannel-logout`.
- `oauth2-logout` is the RP-Initiated Logout configuration for OIDC Providers not following the standard (logout endpoint missing from the OpenID configuration or exotic request parameter names)
- as both the UI and REST API are served through the gateway, there are no cross-origin requests and we don't need CORS configuration
```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        # OpenID Providers configuration (shared by client and resource server filter-chains)
        ops:
        - iss: ${keycloak-issuer}
          username-claim: preferred_username
          authorities:
          - path: $.realm_access.roles
          - path: $.resource_access.*.roles
        - iss: ${cognito-issuer}
          username-claim: username
          authorities:
          - path: cognito:groups
        - iss: ${auth0-issuer}
          username-claim: $['https://c4-soft.com/user']['name']
          authorities:
          - path: $['https://c4-soft.com/user']['roles']
          - path: $.permissions
        # Configuration for an OAuth2 client security filter-chain: mostly login, logout and CSRF protection
        client:
          client-uri: ${gateway-uri}
          # Intercept only requests which need a session
          # Other requests will go through the resource server filter-chain (which has lowest precedence and no security matcher)
          security-matchers: 
          - /login/**
          - /oauth2/**
          - /
          - /login-options
          - /logout
          - /me
          - /bff/**
          permit-all:
          - /login/**
          - /oauth2/**
          - /
          - /login-options
          - /me
          # The Angular app needs access to the CSRF cookie (to return its value as X-XSRF-TOKEN header)
          csrf: cookie-accessible-from-js
          login-path: /ui/
          post-login-redirect-path: /ui/
          post-logout-redirect-path: /ui/
          # This is an "experemiental" feature, use with caution
          back-channel-logout-enabled: true
          # Auth0 and Cognito do not follow strictly the OpenID RP-Initiated Logout spec and need specific configuration
          oauth2-logout:
            cognito-confidential-user:
              uri: https://spring-addons.auth.us-west-2.amazoncognito.com/logout
              client-id-request-param: client_id
              post-logout-uri-request-param: logout_uri
            auth0-confidential-user:
              uri: ${auth0-issuer}v2/logout
              client-id-request-param: client_id
              post-logout-uri-request-param: returnTo
          # Auth0 requires client to provide with audience in authorization-code request
          authorization-request-params:
            auth0-confidential-user:
              - name: audience
                value: demo.c4-soft.com
        # Configuration for a resource server security filterchain
        resourceserver:
          permit-all:
          - /resource-server/**
          - /ui/**
          - /v3/api-docs/**
          - /actuator/health/readiness
          - /actuator/health/liveness
          - /.well-known/acme-challenge/**
```
After that, we have Boot configuration for actuator and logs
```yaml
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
    root: INFO
    org:
      springframework:
        security: INFO
```
The last section is a Spring profile to enable SSL, adapt the scheme for our client absolute URIs as well as scheme and port used for the local Keycloak instance:
```yaml
---
spring:
  config:
    activate:
      on-profile: ssl
  cloud:
    gateway:
      default-filters:
      - DedupeResponseHeader=Access-Control-Allow-Credentials Access-Control-Allow-Origin
      - SaveSession
      - SecureHeaders
server:
  ssl:
    enabled: true

scheme: https
keycloak-port: 8443
```

### 2.5. Web Security Configuration
Thanks to `spring-addons-starter-oidc`, the client and resource server security filter-chains are already provided and ordered, so we have nothing to do.

### 2.6. Gateway Controller
There are end-points that we will expose from the gateway itself:
- `/login-options` to get a list of available options to initiate an authorization-code flow. This list is build from clients registration repository
- `/me` to get some info about the current user, retrieved from the `Authentication` in the security context (if the user is authenticated, an empty "anonymous" user is returned otherwise).
- `/logout` to invalidate current user session and get the URI of the request to terminate the session on the identity provider. The implementation proposed here builds the RP-Initiated Logout request URI and then executes the same logic as `SecurityContextServerLogoutHandler`, which is the default logout handler.
```java
@RestController
@Tag(name = "Gateway")
public class GatewayController {
	private final ReactiveClientRegistrationRepository clientRegistrationRepository;
	private final SpringAddonsOidcClientProperties addonsClientProperties;
	private final LogoutRequestUriBuilder logoutRequestUriBuilder;
	private final ServerSecurityContextRepository securityContextRepository = new WebSessionServerSecurityContextRepository();
	private final List<LoginOptionDto> loginOptions;

	public GatewayController(
			OAuth2ClientProperties clientProps,
			ReactiveClientRegistrationRepository clientRegistrationRepository,
			SpringAddonsOidcProperties addonsProperties,
			LogoutRequestUriBuilder logoutRequestUriBuilder) {
		this.addonsClientProperties = addonsProperties.getClient();
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.logoutRequestUriBuilder = logoutRequestUriBuilder;
		this.loginOptions = clientProps.getRegistration().entrySet().stream().filter(e -> "authorization_code".equals(e.getValue().getAuthorizationGrantType()))
				.map(
						e -> new LoginOptionDto(
								e.getValue().getProvider(),
								"%s/oauth2/authorization/%s".formatted(addonsClientProperties.getClientUri(), e.getKey())))
				.toList();
	}

	@GetMapping(path = "/login-options", produces = "application/json")
	@Tag(name = "getLoginOptions")
	public Mono<List<LoginOptionDto>> getLoginOptions(Authentication auth) throws URISyntaxException {
		final boolean isAuthenticated = auth instanceof OAuth2AuthenticationToken;
		return Mono.just(isAuthenticated ? List.of() : this.loginOptions);
	}

	@GetMapping(path = "/me", produces = "application/json")
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

	@PutMapping(path = "/logout", produces = "application/json")
	@Tag(name = "logout")
	@Operation(responses = { @ApiResponse(responseCode = "204") })
	public Mono<ResponseEntity<Void>> logout(ServerWebExchange exchange, Authentication authentication) {
		final Mono<URI> uri;
		if (authentication instanceof OAuth2AuthenticationToken oauth && oauth.getPrincipal() instanceof OidcUser oidcUser) {
			uri = clientRegistrationRepository.findByRegistrationId(oauth.getAuthorizedClientRegistrationId()).map(clientRegistration -> {
				final var uriString = logoutRequestUriBuilder
						.getLogoutRequestUri(clientRegistration, oidcUser.getIdToken().getTokenValue(), addonsClientProperties.getPostLogoutRedirectUri());
				return StringUtils.hasText(uriString) ? URI.create(uriString) : addonsClientProperties.getPostLogoutRedirectUri();
			});
		} else {
			uri = Mono.just(addonsClientProperties.getPostLogoutRedirectUri());
		}
		return uri.flatMap(logoutUri -> {
			return securityContextRepository.save(exchange, null).thenReturn(logoutUri);
		}).map(logoutUri -> {
			return ResponseEntity.noContent().location(logoutUri).build();
		});
	}

	static record UserDto(String subject, String issuer, List<String> roles) {
		static final UserDto ANONYMOUS = new UserDto("", "", List.of());
	}

	static record LoginOptionDto(@NotEmpty String label, @NotEmpty String loginUri) {
	}
}
```

## 3. Resource Server
This resource server will expose a single `/greetings` endpoint returning a message with user data retrieved from the **access token** (as oposed to the "client" `/me` endpoint which uses data from the ID token)

### 3.1. Project Initialization
From [https://start.spring.io](https://start.spring.io) download a new project with:
- Spring Web
- OAuth2 Resource Server
- Spring Boot Actuator

and then add this dependencies:
- [`spring-addons-starter-oidc`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-starter-oidc)
- [`spring-addons-starter-oidc-test`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-starter-oidc-test)
- [`swagger-annotations-jakarta`](https://central.sonatype.com/artifact/io.swagger.core.v3/swagger-annotations-jakarta/2.2.8) for a cleaner OpenAPI specification (if the maven `openapi` profile, which is omitted in the tutorial but included in the source, is activted)

### 3.2. Application Properties
The structure is mostly the same as for the BFF (we only remove the `client` part):
```yaml
scheme: http
origins:  ${scheme}://localhost:8080
keycloak-port: 8442
keycloak-issuer: ${scheme}://localhost:${keycloak-port}/realms/master
cognito-issuer: https://cognito-idp.us-west-2.amazonaws.com/us-west-2_RzhmgLwjl
auth0-issuer: https://dev-ch4mpy.eu.auth0.com/

server:
  port: 6443
  error:
    include-message: always
  shutdown: graceful
  ssl:
    enabled: false

spring:
  lifecycle:
    timeout-per-shutdown-phase: 30s

com:
  c4-soft:
    springaddons:
      oidc:
        ops:
        - iss: ${keycloak-issuer}
          username-claim: preferred_username
          authorities:
          - path: $.realm_access.roles
          - path: $.resource_access.*.roles
        - iss: ${cognito-issuer}
          username-claim: username
          authorities:
          - path: cognito:groups
        - iss: ${auth0-issuer}
          username-claim: $['https://c4-soft.com/user']['name']
          authorities:
          - path: roles
          - path: permissions
        resourceserver:
          permit-all: 
          - "/public/**"
          - "/actuator/health/readiness"
          - "/actuator/health/liveness"
          - "/v3/api-docs/**"
        
logging:
  level:
    root: INFO
    org:
      springframework:
        security: INFO
        
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

### 3.3. Web Security Customization
A resource server security filter-chain is auto-configured by spring-addons. Here, we'll define some security configuration to switch successful authorizations from the default `JwtAuthenticationToken` to `OAuthentication<OpenidClaimSet>` (explore its API in the controller if you wonder why):
```java
@Configuration
@EnableMethodSecurity
public static class WebSecurityConfig {
	@Bean
	JwtAbstractAuthenticationTokenConverter authenticationConverter(
			Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
			SpringAddonsOidcProperties addonsProperties) {
		return jwt -> new OAuthentication<>(
				new OpenidClaimSet(jwt.getClaims(), addonsProperties.getOpProperties(jwt.getClaims().get(JwtClaimNames.ISS)).getUsernameClaim()),
				authoritiesConverter.convert(jwt.getClaims()),
				jwt.getTokenValue());
	};
}
```

### 3.4. REST Controller
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

	public static record GreetingDto(String message) {
	}
}
```

## 4. Browser client
The details of creating an Angular workspace with an application and two client libraries generated with the `openapi-generator-cli` from OpenAPI specifications (itself generated by a maven plugin in our Spring projects) goes beyond the aim of this tutorial.

Make sure you run `npm i` before you `ng serve` the application. This will pull all the necessary dependencies and also generate the client libraries for the Gateway and Greeting APIs (which are documented with OpenAPI).

The important things to note here are:
- we expose a public landing page (accessible to anonymous users)
- the Angular app queries the gateway for the login options it proposes and then renders a page for the user to choose one
- for security reasons, login and logout redirections are made by setting `window.location.href` (see `UserService`) implementation
- still for security reasons, the logout is a `PUT`. It invalidates the user session on the BFF and returns, in a `location` header, an URI for a `GET` request to invalidate the session on the authorization server (identity provider). It's ok for the second request to be a get becasue it should contain the ID token associated with the session to invalidate (which acts like a CSRF token in this case).
- for CSRF token to be sent, the API calls are issued with relative URLs (`/api/greet` and not `https://localhost:8080/api/greet`)
