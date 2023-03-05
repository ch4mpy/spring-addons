# Mix OAuth2 Client and Resource-Server Configurations in a Single Application
The aim here is to **configure a Spring back-end as both OAuth2 client and resource-server while allowing users to authenticate among a list of heterogeneous trusted authorization-servers**: a local Keycloak realm as well as remote Auth0 and Cognito instances.

## 1. Preamble
It is important to note that in this configuration, the browser **is not an OAuth2 client**: it is secured with regular sessions, which must be enabled on the `SecurityFilterChain` dedicated to login, logout and UI resources.

From the security point of view, the application is split in two parts
- OAuth2 client which handles OAuth2 flows and renders UI elements
- OAuth2 resource-server which is the REST API.

What we will see here is a rathor long journey mostly because we chose to demo a scenario where users can login from more than just one identity provider: **have active sessions with Keycloak and Auth0 and Cognito at the same time** (not or), which clearly wasn't a use-case spring-security developpers had in mind when creating `OAuth2AuthenticationToken`, the `Authentication` implementation for OAuth2 clients. We will get around this limitations by using the user session to store the identity data we need to retrieve the right authorized client and send logout requests with the right ID-Token. **If we were interested in single tenant scenario only, things would get much simpler and we'll see how too**.

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
  * a "greet" page where the user can
    - get a greeting for each of the identity providers he his connected to
    - add an identity from one of the configured identity providers he is not authenticated against yet
    - logout from the identity providers he is connected to either individually or all of it
    - invalidate his session from the Thymeleaf client without disconecting from identity providers

Here is what we will build should look like:
![greeting page screen-shot](https://github.com/ch4mpy/spring-addons/blob/master/samples/tutorials/resource-server_with_ui/readme-resources/greet.png)

## 3. Project Initialisation
We'll start a spring-boot 3 project from https://start.spring.io/ with those dependencies:
- lombok
- spring-boot-starter-web (used by both REST API and UI servlets)
- spring-boot-starter-webflux (required for WebClient, used to query the REST API from the UI `@Controller`)
- spring-boot-starter-oauth2-client
- spring-boot-starter-thymeleaf
- spring-boot-starter-actuator

And then add those dependencies:
- [`spring-addons-webmvc-jwt-resource-server`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-webmvc-jwt-resource-server/6.1.1)
- [`spring-addons-webmvc-client`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-webmvc-client/6.1.1)
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
We will also use `SpringAddonsOAuth2ClientProperties` to configure non OIDC standard logout handlers.

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
SecurityFilterChain oauth2ClientFilterChain(
			HttpSecurity http,
			ServerProperties serverProperties,
			OAuth2AuthorizationRequestResolver authorizationRequestResolver,
			SpringAddonsOAuth2ClientProperties clientProps,
			SpringAddonsSecurityProperties addonsProps,
			Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter)
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
Thanks to auto-configuration, nothing to do there: `spring-addons-*-client` provides with the same `ConfigurableClaimSet2AuthoritiesConverter` as `spring-addons-*-*-resource-server`. The properties already defined for the resource-server filter chain are picked there too.

As usual with spring-addons, this authorities mapper is a `@ConditionalOnMissingBean`, and if we expose our own `Converter<Map<String, Object>, Collection<? extends GrantedAuthority>>` bean, it would take precedence.

### 4.3. OAuth2 Login Configuration
One of the TODOs we left in the client security filter-chain concerns authenticating the client on behalf of a user. This is a 4 steps ladder:
- use a custom login page served by the UiController. This page should parse the configuration and propose a login option for each of the clients with authorization-code listed in application properties
- use the `OAuth2AuthorizationRequestResolver` auto-configured by spring-addons. This beans allows us to define (in properties) the hostanme and port to use for building authorization-code callback URIs.
- redirect successfuly  authenticated users to an index page. We will use our greetings page for that.
- Use a custom user service with two responsibilities:
  * map user roles from OpenID private claims to spring-security authorities
  * as the user `subject` (unique ID of the user on a given authorization server) and ID-Token will change with each provider the user is connected to, we'll use a map to save this data in session.

#### 4.3.1. `OAuth2UserService`
Here is the user service we'll use:
```java
@Data
@RequiredArgsConstructor
static class C4OAuth2UserService implements OAuth2UserService<OidcUserRequest, OidcUser> {
	private final Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter;

	@Override
	public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
		HttpSessionSupport.addIdentity(
				userRequest.getClientRegistration().getRegistrationId(),
				userRequest.getIdToken().getClaims().get(StandardClaimNames.SUB).toString(),
				userRequest.getIdToken().getTokenValue());

		final var authorities = authoritiesConverter.convert(userRequest.getIdToken().getClaims());
		return new DefaultOidcUser(authorities, userRequest.getIdToken());
	}

}
```

#### 4.3.2. Static Access to `HttpSession`
To access (and update) the current session, we can use such a support class:
```java
public class HttpSessionSupport {
	private static final String SESSION_KEY_C4_SPRING_ADDONS_IDENTITIES_BY_REGISTRATION_ID = "c4.spring-addons.identitiesByRegistrationId";

	public static HttpSession getSession() {
		ServletRequestAttributes attr = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
		HttpSession session = attr.getRequest().getSession();
		return session;
	}

	public static Map<String, Identity> getIdentitiesByRegistrationId() {
		final var session = getSession();
		@SuppressWarnings("unchecked")
		final var identitiesByRegistrationId = (Map<String, Identity>) session.getAttribute(SESSION_KEY_C4_SPRING_ADDONS_IDENTITIES_BY_REGISTRATION_ID);
		return identitiesByRegistrationId == null ? Map.of() : identitiesByRegistrationId;
	}

	static Map<String, Identity> setIdentitiesByRegistrationId(Map<String, Identity> identitiesByRegistrationId) {
		final var session = getSession();
		final var updated = Collections.unmodifiableMap(identitiesByRegistrationId);
		session.setAttribute(SESSION_KEY_C4_SPRING_ADDONS_IDENTITIES_BY_REGISTRATION_ID, updated);
		return updated;
	}

	public static void invalidate() {
		getSession().invalidate();
	}

	public static Map<String, Identity> addIdentity(String registrationId, String subject, String idToken) {
		final var identity = new Identity(subject, idToken);
		final var identitiesByRegistrationId = new HashMap<>(getIdentitiesByRegistrationId());
		identitiesByRegistrationId.put(registrationId, identity);
		return setIdentitiesByRegistrationId(identitiesByRegistrationId);
	}

	public static Map<String, Identity> removeIdentity(String registrationId) {
		final var identitiesByRegistrationId = new HashMap<>(getIdentitiesByRegistrationId());
		identitiesByRegistrationId.remove(registrationId);
		return setIdentitiesByRegistrationId(identitiesByRegistrationId);
	}

	public static String getUserSubject(String clientRegistrationId) {
		return Optional.ofNullable(getIdentitiesByRegistrationId().get(clientRegistrationId)).map(Identity::getSubject).orElse(null);
	}

	public static String getUserIdToken(String clientRegistrationId) {
		return Optional.ofNullable(getIdentitiesByRegistrationId().get(clientRegistrationId)).map(Identity::getIdToken).orElse(null);
	}

	@Data
	@RequiredArgsConstructor
	public static class Identity {
		private final String subject;
		private final String idToken;
	}
}
```

#### 4.3.3. Security Filter-Chain
And now, let's update our client `SecurityFilterChain` bean with OAuth2 login configuration:
```java
http.oauth2Login()
      .loginPage("%s/login".formatted(clientProps.getClientUri()))
      .authorizationEndpoint().authorizationRequestResolver(authorizationRequestResolver).and()
      // When SSL is enabled, redirections are made to port 8443 instead of actual client port. Fix that.
      .defaultSuccessUrl("%s/ui/greet".formatted(clientProps.getClientUri()), true)
      .userInfoEndpoint().oidcUserService(new C4OAuth2UserService(authoritiesConverter));
```

### 4.4. Logout Configuration
This one is tricky. It is important to have in mind that each user has a session on our client but also on each authorization server.

If we invalidate only the session on our client, it is very likely that the next login attempt with the same browser will complete silently. For a complete logout, **both client and authorization sessions should be terminatedt**.

OIDC specifies two logout protocols:
- [RP-initiated logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) where a client asks the authorization-server to terminate a user session
- [back-channel logout](https://openid.net/specs/openid-connect-backchannel-1_0.html) where the authorization-server brodcasts a logout event to a list of registered clients so that each can terminate its own session for the user

#### 4.4.1 RP-Initiated Logout
In the case of a single "OIDC" authorization-server strictly following the RP-Initiated Logout standard, we could use the `OidcClientInitiatedLogoutSuccessHandler` from spring security:
```java
http.logout().logoutSuccessHandler(new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository));
```
But this is not applicable here for two reasons:
- This handler is not ready for multi-tenancy: it will terminate the session only on the last identity provider the user identified against.
- In the three identity providers we use in this tutorial, only Keycloak conformes to RP-Initiated Logout. Neither Auth0 nor Cognito `.well-known/openid-configuration` expose an `end_session_endpoint` and the `logout` end-points they document respectively [here](https://auth0.com/docs/api/authentication#logout) and [there](https://docs.aws.amazon.com/cognito/latest/developerguide/logout-endpoint.html) do not follow the standard. To make things even more complicated, Cognito logout URI does not have the same `host` as the issuer...

If we ever had a single identity provider that would "almost" comply with RP-Initiated Logout, instead of all that we'll do here, we could have used `SpringAddonsOAuth2LogoutSuccessHandler` which is auto-configured with `SpringAddonsOAuth2ClientProperties` (refer to the respective Javadoc for more details).

Now, let's address our use case: OAuth2 client with potentially several authorized clients simultaneously. [`spring-addons-webmvc-client`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-webmvc-client/6.1.1) provides with a configurable logout request URI builder authorization-server implementing "close to [RP-initiated logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) standard", which is the case of both [Auth0](https://auth0.com/docs/api/authentication#logout) and [Cognito](https://docs.aws.amazon.com/cognito/latest/developerguide/logout-endpoint.html) that will be of great help for us in the following 3 logout endpoints we'll expose:
- `/logout`, the default Spring Boot endpoint, used to invalidate our client session only (and try the silent re-login exposed above)
- `/ui/logut-idp` to invalidate the session on a specific identity provider and remove the corresponding entries in session and `OAuth2AuthorizedClientService`
- `/ui/bulk-logout-idps` to terminate sessions on all the identity providers the user is authorized on, as well as our client session.

As RP-Initiated logout is using redirections to the authorization server (on logout URI) and then back to the client (on post-logout URI), we'll have to ensure that all our application `/`, `/ui/greet` and `/ui/bulk-logout-idps` endpoints are declared as allowed post-logout URIs on all identity providers.

As most logout logic will be handled on custom `@Controller` endpoints, all we need to declare in the security filter-chain is the default logout endpoint:
```java
http.logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
```

#### 4.4.2. Back-Channel Logout
Back-channel logout [is not implemented yet in spring-security](https://github.com/spring-projects/spring-security/issues/7845) (vote there if you are interested in it). We'll have to implement it ourselves. If you're interested in it, come again later, this is still a work in progress.

### 4.5. `WebClient` in Servlet Applications
As we use `WebClient`, which is a reactive compenent, in a servlet application, we have to tweak its auto-configuration:
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
Non-standard logouts are then registered with properties under `com.c4-soft.springaddons.security.client` for each issuer, spring OIDC handler being used as default for non listed ones.

### 4.6. Multi-Tenant Properties
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
It might not be trivial to configure the authorization-server and retrieve all the configuration values we needed here, but with this properties, **we defined 3 authorization-servers for both client and resource-server, and we could define for each how to map username and roles along with how to perform logout on non-standard end-points!**.

To implement a single tenant scenario, we would keep just a single entry in `spring.security.oauth2.client.provider`, `com.c4-soft.springaddons.security.issuers` and `com.c4-soft.springaddons.security.client.oauth2-logout` arrays. That easy.

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
We'll need a few resources: a static index as well as a a pair of templates with a controllers to serve it.

What we'll see here is specific to multi-tenancy needs. With a single identity provider, we'd redirect the user directly to the authentication endpoint instead of displaying a page to choose login options and configure the standard logout endpoint with a `LogoutSuccessHandler` adapted to the authorization server logout endpoint (see `SpringAddonsOAuth2LogoutSuccessHandler` Javadoc).

### 6.1. Login
The first thing we need is a login page with links to initiate user authentication to each of the registered client with `authorization-code` flow.

If we were in a single provider scenario, we'd probably redirect the user

#### 6.1.1. Controller Endpoint
By iterating over `OAuth2ClientProperties` and filtering only the registrations with authorization-code, we can generate the link to the authorization flow initiation for each identity provider:
```java
@Controller
@RequiredArgsConstructor
public class LoginController {
	private final OAuth2ClientProperties clientProps;

	@GetMapping("/login")
	public String getLogin(Model model, Authentication auth) throws URISyntaxException {
		final var loginOptions =
				clientProps.getRegistration().entrySet().stream().filter(e -> "authorization_code".equals(e.getValue().getAuthorizationGrantType()))
						.map(e -> new LoginOptionDto(e.getValue().getProvider(), e.getKey())).toList();

		model.addAttribute("isAuthenticated", auth != null && auth.isAuthenticated());
		model.addAttribute("loginOptions", loginOptions);

		return "login";
	}

	@Data
	@AllArgsConstructor
	static class LoginOptionDto implements Serializable {
		private static final long serialVersionUID = -7598910797375105284L;

		private final String label;
		private final String provider;
	}
}
```

#### 6.1.2. Thymeleaf Template
Here is a `src/main/resources/templates/login.html` displaying the data assembled just above:
```html
<!DOCTYPE html>
<html lang="en">

<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
	<meta name="description" content="">
	<meta name="author" content="">
	<title>Login</title>
	<link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css" rel="stylesheet"
		integrity="sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M" crossorigin="anonymous">
	<link href="https://getbootstrap.com/docs/4.0/examples/signin/signin.css" rel="stylesheet"
		crossorigin="anonymous" />
</head>

<body>
	<div class="container">
		<div th:if="${!isAuthenticated}">
			<h2 class="form-signin-heading">Choose an authorization server</h2>
			<table class="table table-striped">
				<tr th:each="client : ${loginOptions}">
					<td><a th:href="@{/oauth2/authorization/{provider}(provider=${client.provider})}"
							th:utext="@{Login with {label}(label=${client.label})}">..!..</a></td>
				</tr>
			</table>

		</div>
		<div th:if="${isAuthenticated}">
			<p>You're already logged in. Logout before you can choose another authorization server.</p>
			<a href="/bulk-logout-idps"><button type="button">Logout</button></a>
		</div>
	</div>
</body>

</html>
```

### 6.2. Greetings Page
This is the core part of our client. It will control:
- login initiation to identity providers the user is not identified against yet
- greet message fetching from the API with each of the authorized clients
- individual logout from each provider
- client session termination without terminating identity providers ones
- "bulk" logout from all the identity providers the user has logged in (one after the other with redirects) followed by client session invalidation.

#### 6.2.1. Controller Endpoints
This is the big part. We will need all of the following beans to be injected into our controller (the first 3 are auto-configured by Spring Boot "official" starter and the last 2 by `spring-addons-webmvc-client`):
- `WebClient`
- `InMemoryClientRegistrationRepository`
- `OAuth2AuthorizedClientService`
- `SpringAddonsOAuth2ClientProperties`
- `LogoutRequestUriBuilder`

The `/ui/greet` endpoint is responsible for assembling the data about 
- authorized clients with greeting message and individual logout link
- unauthorized clients with login link
```java
@GetMapping("/greet")
@PreAuthorize("isAuthenticated()")
public String getGreeting(HttpServletRequest request, Model model) throws URISyntaxException {
	final var unauthorizedClients = new ArrayList<UnauthorizedClientDto>();
	final var authorizedClients = new ArrayList<AuthorizedClientDto>();
	StreamSupport.stream(this.clientRegistrationRepository.spliterator(), false)
			.filter(registration -> AuthorizationGrantType.AUTHORIZATION_CODE.equals(registration.getAuthorizationGrantType())).forEach(registration -> {
				final var subject = HttpSessionSupport.getUserSubject(registration.getRegistrationId());
				final var authorizedClient =
						subject == null ? null : authorizedClientService.loadAuthorizedClient(registration.getRegistrationId(), subject);
				if (authorizedClient == null) {
					unauthorizedClients.add(new UnauthorizedClientDto(registration.getClientName(), registration.getRegistrationId()));
				} else {
					try {
						final var greetApiUri = new URI(
								addonsClientProps.getClientUri().getScheme(),
								null,
								addonsClientProps.getClientUri().getHost(),
								addonsClientProps.getClientUri().getPort(),
								"/api/greet",
								null,
								null);
						final var response = authorize(api.get().uri(greetApiUri), registration.getRegistrationId())
								.exchangeToMono(r -> r.toEntity(String.class)).block();

						authorizedClients.add(
								new AuthorizedClientDto(
										registration.getClientName(),
										response.getStatusCode().is2xxSuccessful() ? response.getBody() : response.getStatusCode().toString(),
										"/ui/logout-idp?clientRegistrationId=%s".formatted(registration.getRegistrationId())));

					} catch (RestClientException | URISyntaxException e) {
						final var error = e.getMessage();
						authorizedClients.add(new AuthorizedClientDto(registration.getClientName(), error, registration.getRegistrationId()));

					}

				}
			});
	model.addAttribute("unauthorizedClients", unauthorizedClients);
	model.addAttribute("authorizedClients", authorizedClients);
	return "greet";
}

@Data
@NoArgsConstructor
@AllArgsConstructor
public static class AuthorizedClientDto implements Serializable {
	private static final long serialVersionUID = -6623594577844506618L;

	private String label;
	private String message;
	private String logoutUri;
}
```

We also need an endpoint listening to individual logout requests to:
- remove identity data for that provider from the session
- remove the client from authorized clients service
- invalidate the client session if there are no more authorized clients
- redirect the user to the right identity provider logout endpoint
```java
@GetMapping("/logout-idp")
@PreAuthorize("isAuthenticated()")
public RedirectView logout(
		@RequestParam("clientRegistrationId") String clientRegistrationId,
		@RequestParam(name = "redirectTo", required = false) Optional<String> redirectTo) {
	final var subject = HttpSessionSupport.getUserSubject(clientRegistrationId);
	final var idToken = HttpSessionSupport.getUserIdToken(clientRegistrationId);
	final var authorizedClient = authorizedClientService.loadAuthorizedClient(clientRegistrationId, subject);
	final var postLogoutUri = UriComponentsBuilder.fromUri(addonsClientProps.getClientUri()).path(redirectTo.orElse("/ui/greet"))
			.encode(StandardCharsets.UTF_8).build().toUriString();
	String logoutUri = logoutRequestUriBuilder.getLogoutRequestUri(authorizedClient, idToken, URI.create(postLogoutUri));

	log.info("Remove authorized client with ID {} for {}", clientRegistrationId, subject);
	this.authorizedClientService.removeAuthorizedClient(clientRegistrationId, subject);
	final var remainingIdentities = HttpSessionSupport.removeIdentity(clientRegistrationId);
	if (remainingIdentities.size() == 0) {
		HttpSessionSupport.invalidate();
	}

	log.info("Redirecting {} to {} for logout", subject, logoutUri);
	return new RedirectView(logoutUri);
}
```

Last is the endpoint for the "bulk" logout, closing all opened sessions on identity providers. This is a smart game of redirections to our individual logout endpoint:
```java
@GetMapping("/bulk-logout-idps")
@PreAuthorize("isAuthenticated()")
public RedirectView bulkLogout() {
	final var identities = HttpSessionSupport.getIdentitiesByRegistrationId().entrySet().iterator();
	if (identities.hasNext()) {
		final var userId = identities.next();
		final var builder = UriComponentsBuilder.fromPath("/ui/logout-idp");
		builder.queryParam("clientRegistrationId", userId.getKey());
		builder.queryParam("redirectTo", "/ui/bulk-logout-idps");
		return new RedirectView(builder.encode(StandardCharsets.UTF_8).build().toUriString());

	}
	return new RedirectView("/");
}
```

#### 6.2.2. Thymeleaf Template
We also need a `src/main/resources/templates/greet.html` template to display the greeting fetched from the API:
```html
<!DOCTYPE HTML>
<html xmlns:th="http://www.thymeleaf.org">

<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
	<meta name="description" content="">
	<meta name="author" content="">
	<title>Greetings!</title>
	<link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css" rel="stylesheet"
		integrity="sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M" crossorigin="anonymous">
	<link href="https://getbootstrap.com/docs/4.0/examples/signin/signin.css" rel="stylesheet"
		crossorigin="anonymous" />
</head>

<body>
	<div class="container">
		<h1 class="form-signin-heading">Greetings from the REST API</h1>
		<div>
			<table class="table table-striped">
				<tr th:each="client : ${authorizedClients}">
					<td th:utext="${client.label}">..!..</td>
					<td th:utext="${client.message}">..!..</td>
					<td><a th:href="${client.logoutUri}"><button type="button">Logout</button></a></td>
				</tr>
			</table>
		</div>
		<div th:if="${unauthorizedClients.size() > 0}">
			<h2>Available authorization servers</h2>
			<table class="table table-striped">
				<tr th:each="client : ${unauthorizedClients}">
					<td th:utext="${client.label}">..!..</td>
					<td></td>
					<td><a th:href="@{/oauth2/authorization/{registrationId}(registrationId=${client.registrationId})}"><button
								type="button">Login</button></a></td>
				</tr>
			</table>
		</div>
		<div th:if="${authorizedClients.size() > 0}">
			<h2>Logout options</h2>
			<table class="table table-striped">
				<tr>
					<td><a href="/logout"><button type="button">Invalidate Session</button></a></td>
					<td>This will terminate your session on this client only.
						You will keep your session on the authorization-servers and
						potentially be silently logged in next time you attempt to authenticate on it.</td>
				</tr>
				<tr>
					<td><a href="/ui/bulk-logout-idps"><button type="button">Bulk Logout</button></a></td>
					<td>This will terminate your session on each authorization server you are connected to.</td>
				</tr>
			</table>
		</div>
</body>
```

## 7. Conclusion
In this tutorial we saw how to configure different security filter-chains and select to which routes each applies. We set-up
- an OAuth2 client filter-chain with login, logout and sessions (and CSRF protection) for UI
- a state-less (neither session nor CSRF protection) filter-chain for the REST API

This was a rather long journey mostly because we chose to:
- enable multi-tenancy on a Spring OAuth2 client, which is very partly implemented by spring-security: `OAuth2AuthenticationToken` which is the implementation used for OAuth2 clientsclearly wasn't designed with that usage in mind
- use authorization-servers which do not comply with RP-Initiated Logout specifications

We also saw how handy `spring-addons-webmvc-jwt-resource-server` and `spring-addons-webmvc-client` when it comes to configuring respectively OAuth2 resource servers and OAuth2 clients, specially in multi-tenant scenario. But, after all, a single-tenant scenario is just the simplest case of multi-tenant ones and what we did here applies almost everywhere.
