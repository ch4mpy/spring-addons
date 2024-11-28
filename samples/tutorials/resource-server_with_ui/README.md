# Mix OAuth2 Client and Resource Server Configurations in a Single Application
The aim here is to **configure a Spring back-end as both OAuth2 client and resource server while allowing users to authenticate among a list of heterogeneous trusted authorization-servers**: a local Keycloak realm as well as remote Auth0 and Cognito instances.

## 0. Disclaimer
There are quite a few samples, and all are part of CI to ensure that sources compile and all tests pass. Unfortunately, this README is not automatically updated when source changes. Please use it as a guidance to understand the source. **If you copy some code, be sure to do it from the source, not from this README**.

## 1. Preamble
We'll define two distinct and ordered security filter-chains: 
- the 1st with client configuration, with login, logout, and a security matcher limiting it to UI resources
- the 2nd with resource server configuration. As it has no security matcher and a higher order, it intercepts all requests that were not matched by the 1st filter chain and acts as default for all the remaining resources (REST API).

It is important to note that in this configuration, **the browser is not an OAuth2 client**: it is secured with regular sessions. As a consequence, **CSRF and BREACH protection must be enabled** in the client filter-chain.

The UI being secured with session cookies and the REST end-points with JWTs, the Thymeleaf `@Controller` internally uses `WebClient` to fetch data from the API and build the model for the template, authorizing its requests with tokens stored in session.

What we will see here is a rather long journey mostly because we chose to demo a scenario where users can login from more than just one identity provider: **have active sessions with Keycloak and Auth0 and Cognito at the same time** (not "Keycloak or Auth0 or Cognito"), which clearly wasn't a use-case spring-security developers had in mind when creating `OAuth2AuthenticationToken`, the `Authentication` implementation for OAuth2 clients. We will get around this limitations by using the user session to store the identity data we need to retrieve the right authorized client and send logout requests with the right ID-Token. **If we were interested in single tenant scenario only, things would get much simpler and we'll see how too**.

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
  * asking the user to choose between the 3 authentication sources trusted by the resource server
  * sessions are required as requests from browsers won't be authorized with a Bearer token (CSRF protection should be activated too)
  * returning the default 302 (redirect to login) if the user has no session yet
  * an index page, loaded after authentication, with links to Thymeleaf page and Swagger-UI index
  * a login page to select an authorization-server (aka tenant): a local Keycloak realm along with remote Auth0 and Cognito instances
  * defining access-control to all OAuth2 client & UI resources: login, logout, authorization callbacks and Swagger-UI
  * a "greet" page where the user can
    - get a greeting for each of the identity providers he is connected to
    - add an identity from one of the configured identity providers he is not authenticated against yet
    - logout from the identity providers he is connected to either individually or all of it
    - invalidate his session from the Thymeleaf client without disconnecting from identity providers

Here is what we will build should look like:
![greeting page screen-shot](https://github.com/ch4mpy/spring-addons/blob/master/samples/tutorials/resource-server_with_ui/readme-resources/greet.png)

## 3. Project Initialisation
We'll start a spring-boot 3 project from https://start.spring.io/ with these dependencies:
- lombok
- spring-boot-starter-web (used by both REST API and UI servlets)
- spring-boot-starter-webflux (required for WebClient, used to query the REST API from the UI `@Controller`)
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
```yaml
spring:
  security:
    oauth2:
      client:
        provider:
          keycloak:
            issuer-uri: ${keycloak-issuer}
          entra:
            issuer-uri: ${entra-issuer}
        registration:
          keycloak-authorization-code:
            authorization-grant-type: authorization_code
            client-name: Keycloak (local)
            client-id: spring-addons-user
            client-secret: secret
            provider: keycloak
            scope: openid,profile,email,offline_access
          keycloak-client-credentials:
            authorization-grant-type: client_credentials
            client-id: spring-addons-m2m
            client-secret: secret
            provider: keycloak
            scope: openid
          entra:
            authorization-grant-type: authorization_code
            client-name: Microsoft Entra
            client-id: 0866cd01-6f25-4501-8ce5-b89dbfc671e0
            client-secret: change-me
            provider: entra
            scope: api://4f68014f-7f14-4f89-8197-06f0b3ff24d9/spring-addons

com:
  c4-soft:
    springaddons:
      oidc:
        ops:
        - iss: ${keycloak-issuer}
          authorities:
          - path: $.realm_access.roles
        - iss: ${entra-issuer}
          authorities:
          - path: $.groups
        resourceserver:
          permit-all: 
          - /actuator/health/readiness
          - /actuator/health/liveness
          - /v3/api-docs/**
          - /api/public
          - /favicon.ico
        client:
          security-matchers:
          - /login/**
          - /oauth2/**
          - /
          - /ui/**
          - /swagger-ui.html
          - /swagger-ui/**
          permit-all:
          - /login/**
          - /oauth2/**
          - /
          - /ui/**
          - /swagger-ui.html
          - /swagger-ui/**
          client-uri: ${client-uri}
          post-login-redirect-path: /ui/greet
          post-logout-redirect-path: /ui/greet
          pkce-forced: true
      rest:
        client:
          greet-client:
            base-url: ${client-uri}/api
            authorization:
              oauth2:
                oauth2-registration-id: keycloak-authorization-code
```
The properties under `rest` define the configuration for a `RestClient` bean named `greetClient` and using a `registration` with client-credentials to authorize its requests to our REST API.

To implement a single tenant scenario, we would keep just a single entry in `spring.security.oauth2.client.provider`, `com.c4-soft.springaddons.security.issuers` and `com.c4-soft.springaddons.security.client.oauth2-logout` arrays. That easy.

Don't forget to update the issuer URIs as well as client ID & secrets with your own (or to override it with command line arguments, environment variables or whatever).

#### 4.2. OAuth2 Security Filter-Chain
**We have absolutely no Java code to write.** For information purpose, here is approximately what `spring-addons-starter-oidc` configure under the hood with the properties above:
```java
@EnableWebSecurity
@Configuration
public class WebSecurityConf {
    @Order(Ordered.HIGHEST_PRECEDENCE)
    @Bean
    SecurityFilterChain springAddonsBackChannelLogoutClientFilterChain(
            HttpSecurity http,
            ServerProperties serverProperties)
            throws Exception {
        http.securityMatcher(new AntPathRequestMatcher("/backchannel_logout"));
        http.authorizeHttpRequests().anyRequest().permitAll();
        if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
            http.requiresChannel().anyRequest().requiresSecure();
        }
        http.cors().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.csrf().disable();
        return http.build();
    }

    @Order(Ordered.LOWEST_PRECEDENCE - 1)
    @Bean
    SecurityFilterChain oauth2ClientFilterChain(
                HttpSecurity http,
                ServerProperties serverProperties,
                OAuth2AuthorizationRequestResolver authorizationRequestResolver)
            throws Exception {
        boolean isSsl = serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled();
    
        http.securityMatcher(new OrRequestMatcher(
            new AntPathRequestMatcher("/login/**"),
            new AntPathRequestMatcher("/oauth2/**"),
            new AntPathRequestMatcher("/"),
            new AntPathRequestMatcher("/ui/**"),
            new AntPathRequestMatcher("/swagger-ui/**")));
        
        http.authorizeHttpRequests()
            .requestMatchers("/login/**", "/oauth2/**", "/", "/ui/**").permitAll()
            .requestMatchers("/swagger-ui.html", "/swagger-ui/**").permitAll()
            .anyRequest().authenticated();
        
        http.oauth2Login()
                .loginPage("http%s://localhost:8080/login".formatted(isSsl ? "s" : ""))
                .authorizationEndpoint().authorizationRequestResolver(authorizationRequestResolver).and()
                .defaultSuccessUrl("http%s://localhost:8080/ui/greet".formatted(isSsl ? "s" : ""), true);
    
        http.logout();
    
        if (isSsl) {
            http.requiresChannel().anyRequest().requiresSecure();
        }
    
        http.cors().disable();
    
        http.csrf();
    
        return http.build();
    }

    @Order(Ordered.LOWEST_PRECEDENCE)
    @Bean
    SecurityFilterChain springAddonsResourceServerSecurityFilterChain(
            HttpSecurity http,
            ServerProperties serverProperties,
            AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver,
            CorsConfigurationSource corsConfigurationSource)
            throws Exception {
        http.oauth2ResourceServer(oauth2 -> oauth2.authenticationManagerResolver(authenticationManagerResolver));
		
		http.authorizeHttpRequests()
			.requestMatchers("/actuator/health/readiness", "/actuator/health/liveness").permitAll()
			.requestMatchers("/v3/api-docs/**").permitAll()
			.requestMatchers("/api/public").permitAll()
			.anyRequest().authenticated();

        http.cors().disable();

        http.csrf().disable();

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		http.exceptionHandling().authenticationEntryPoint((request, response, authException) -> {
			response.addHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"Restricted Content\"");
			response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
		});

        if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
            http.requiresChannel().anyRequest().requiresSecure();
        }

        return http.build();
    }
}
```

### 4.3. RP-Initiated Logout
This one is tricky. It is important to have in mind that each user has a session on our client but also on each authorization server.

If we invalidate only the session on our client, it is very likely that the next login attempt with the same browser will complete silently. For a complete logout, **both client and authorization sessions should be terminated**.

OIDC specifies two logout protocols:
- [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) where a client asks the authorization-server to terminate a user session
- [back-channel logout](https://openid.net/specs/openid-connect-backchannel-1_0.html) where the authorization-server brodcasts a logout event to a list of registered clients so that each can terminate its own session for the user

Here, we cover only the RP-Initiated Logout.

In the case of a single "OIDC" authorization-server strictly following the RP-Initiated Logout standard, we could use the `OidcClientInitiatedLogoutSuccessHandler` from spring security:
```java
http.logout().logoutSuccessHandler(new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository));
```
But this is not applicable here for two reasons:
- This handler is not ready for multi-tenancy: it will terminate the session only on the last identity provider the user identified against.
- In the three identity providers we use in this tutorial, only Keycloak conformes to RP-Initiated Logout. Neither Auth0 nor Cognito `.well-known/openid-configuration` expose an `end_session_endpoint` and the `logout` end-points they document respectively [here](https://auth0.com/docs/api/authentication#logout) and [there](https://docs.aws.amazon.com/cognito/latest/developerguide/logout-endpoint.html) do not follow the standard. To make things even more complicated, Cognito logout URI does not have the same `host` as the issuer...

If we ever had a single identity provider that would "almost" comply with RP-Initiated Logout, instead of all that we'll do here, we could have used `SpringAddonsOAuth2LogoutSuccessHandler` which is auto-configured with `SpringAddonsOAuth2ClientProperties` (refer to the respective Javadoc for more details).

Now, let's address our use case: OAuth2 client with potentially several authorized clients simultaneously. [`spring-addons-webmvc-client`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-webmvc-client/6.1.5) provides with a configurable logout request URI builder authorization-server implementing "close to [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) standard", which is the case of both [Auth0](https://auth0.com/docs/api/authentication#logout) and [Cognito](https://docs.aws.amazon.com/cognito/latest/developerguide/logout-endpoint.html) that will be of great help for us in the following 3 front-channel logout endpoints we'll expose:
- `/logout`, the default Spring Boot endpoint, used to invalidate our client session only (and try the silent re-login exposed above)
- `/ui/logut-idp` to invalidate the session on a specific identity provider and remove the corresponding entries in session and `OAuth2AuthorizedClientService`
- `/ui/bulk-logout-idps` to terminate sessions on all the identity providers the user is authorized on, as well as our client session.

As RP-Initiated Logout is using redirections to the authorization server (on logout URI) and then back to the client (on post-logout URI), we'll have to ensure that all our application `/`, `/ui/greet` and `/ui/bulk-logout-idps` endpoints are declared as allowed post-logout URIs on all identity providers.

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
- `InMemoryClientRegistrationRepository clientRegistrationRepository`
- `OAuth2AuthorizedClientRepository authorizedClientRepo`
- `AuthorizedSessionRepository authorizedSessionRepo`
- `SpringAddonsOidcProperties addonsClientProps`
- `LogoutRequestUriBuilder logoutRequestUriBuilder`

The `/ui/greet` endpoint is responsible for assembling the data about 
- authorized clients with greeting message and individual logout link
- unauthorized clients with login link
```java
@GetMapping("/greet")
@PreAuthorize("isAuthenticated()")
public String getGreeting(HttpServletRequest request, Authentication auth, Model model) throws URISyntaxException {
	final var unauthorizedClients = new ArrayList<UnauthorizedClientDto>();
	final var authorizedClients = new ArrayList<AuthorizedClientDto>();
	StreamSupport.stream(this.clientRegistrationRepository.spliterator(), false)
			.filter(registration -> AuthorizationGrantType.AUTHORIZATION_CODE.equals(registration.getAuthorizationGrantType())).forEach(registration -> {
				final var authorizedClient =
						auth == null ? null : authorizedClientRepo.loadAuthorizedClient(registration.getRegistrationId(), auth, request);
				if (authorizedClient == null) {
					unauthorizedClients.add(new UnauthorizedClientDto(registration.getClientName(), registration.getRegistrationId()));
				} else {
					try {
						final var greetApiUri = new URI(
								addonsClientProps.getClient().getClientUri().getScheme(),
								null,
								addonsClientProps.getClient().getClientUri().getHost(),
								addonsClientProps.getClient().getClientUri().getPort(),
								"/api/greet",
								null,
								null);
						final var response = api.get().uri(greetApiUri)
								.attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
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
		@RequestParam(name = "redirectTo", required = false) Optional<String> redirectTo,
		HttpServletRequest request,
		HttpServletResponse response) {
	final var postLogoutUri = UriComponentsBuilder.fromUri(addonsClientProps.getClient().getClientUri()).path(redirectTo.orElse("/ui/greet"))
			.encode(StandardCharsets.UTF_8).build().toUriString();
	final var authentication = OAuth2PrincipalSupport.getAuthentication(request.getSession(), clientRegistrationId).orElse(null);
	final var authorizedClient = authorizedClientRepo.loadAuthorizedClient(clientRegistrationId, authentication, request);
	final var idToken = authentication instanceof OidcUser oidcUser ? oidcUser.getIdToken().getTokenValue() : null;
	String logoutUri = logoutRequestUriBuilder.getLogoutRequestUri(authorizedClient.getClientRegistration(), idToken, URI.create(postLogoutUri));

	log.info("Remove authorized client with ID {} for {}", clientRegistrationId, authentication.getName());
	this.authorizedClientRepo.removeAuthorizedClient(clientRegistrationId, authentication, request, response);
	final var authorizedClientIds = authorizedSessionRepo.findAuthorizedClientIdsBySessionId(request.getSession().getId());
	if (authorizedClientIds.isEmpty()) {
		request.getSession().invalidate();
	}

	log.info("Redirecting {} to {} for logout", authentication.getName(), logoutUri);
	return new RedirectView(logoutUri);
}
```

Last is the endpoint for the "bulk" logout, closing all opened sessions on identity providers. This is a smart game of redirections to our individual logout endpoint:
```java
@GetMapping("/bulk-logout-idps")
@PreAuthorize("isAuthenticated()")
public RedirectView bulkLogout(HttpServletRequest request) {
	final var authorizedClientIds = authorizedSessionRepo.findAuthorizedClientIdsBySessionId(request.getSession().getId()).iterator();
	if (authorizedClientIds.hasNext()) {
		final var id = authorizedClientIds.next();
		final var builder = UriComponentsBuilder.fromPath("/ui/logout-idp");
		builder.queryParam("clientRegistrationId", id.getClientRegistrationId());
		builder.queryParam("redirectTo", "/ui/bulk-logout-idps");
		return new RedirectView(builder.encode(StandardCharsets.UTF_8).build().toUriString());
	}
	return new RedirectView(addonsClientProps.getClient().getPostLogoutRedirectPath());
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
In this tutorial we saw how to configure different security filter-chains and select to which routes each applies. We set up
- an OAuth2 client filter-chain with login, logout and sessions (and CSRF protection) for UI
- a state-less (neither session nor CSRF protection) filter-chain for the REST API

This was a rather long journey mostly because we chose to:
- enable multi-tenancy on a Spring OAuth2 client, which is very partly implemented by spring-security: `OAuth2AuthenticationToken`, which is the implementation used for OAuth2 clients, clearly wasn't designed with that usage in mind
- use authorization-servers which do not comply with RP-Initiated Logout specifications

We also saw how handy `spring-addons-webmvc-jwt-resource-server` and `spring-addons-webmvc-client` are when it comes to configuring respectively OAuth2 resource servers and OAuth2 clients, specially in multi-tenant scenario. But, after all, a single-tenant scenario is just the simplest case of multi-tenant ones and what we did here applies almost everywhere.
