# Spring Backend

This is a Maven multi-module project with split into two sub-modules:
- `official` depending only on `spring-boot-starter-oauth2-client` and `spring-boot-starter-oauth2-resource-server`
- `with-c4-soft` which uses `spring-addons-starter-oidc` in addition to "official" starters. We'll see that this greatly reduces the amount of Java code and simplifies security configuration

Each of this sub-module is itself split in two:
- a `spring-cloud-gateway` with configuration to use it as OAuth2 BFF
- a REST API configured as stateless resource server.

The aim is to demo:
- a working system with a BFF 
- OAuth2 Spring Security configuration with and without `spring-addons`
- servlet and reactive Security configuration for OAuth2 resource servers
- reactive Security configuration for OAuth2 clients with `authorization-code` flow

## Servlet REST API as stateless resource server
OAuth2 resource servers usually don't need session: the security context is built from the access token.

This makes it insensible to CSRF attacks, but it is not the main benefit: as each request comes with its state embedded, it can be processed by any resource server instance, even one that was just spawned. As so, it makes it much more scalable and fault tolerant than than services relying on sessions as there is no need to share session data between instances or to route all requests from a given user-agent to the same instance.

The Spring `Security(Web)FilterChain` for a resource server should have the following spec:
- be configured as resource server, preferably with JWT decoder for performance reasons
- turn the content of one (or more) private claims containing roles into Spring authorities
- use the most relevant claim as username
- disabled sessions
- disabled CSRF protection (safe when sessions are disabled)
- configured to return 401 when trying to access protected resources (by default Spring returns "302" with redirection to login, but this makes no sense on an authorization server)
- contain some usual access control rules defining at minimum what is accessible to anonymous requests and what requires a valid access token.

### With spring-addons
Absolutely no Java configuration is needed to achieve the above spec and the Security conf only contains the annotation to enable method security:
```java
@Configuration
@EnableMethodSecurity
public class SecurityConf {
}
```

Because Spring Boot properties for resource servers are incompatible with multi-tenant scenarios, the application properties are all specific to spring-addons:
```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        ops:
        - iss: https://localhost:8443/realms/master
          authorities:
          - path: $.realm_access.roles
          username-claim: preferred_username
        resourceserver:
          permit-all:
          - /users/me
          - /actuator/health/readiness
          - /actuator/health/liveness
```

### With just "official" starters
We'll have to write quite some Java code: configure the `JwtAuthenticationConverter` to use the right claims for username and authorities (when possible, otherwize, we'd have to write our own converter) and write the security filter-chain:
```java
@Configuration
@EnableMethodSecurity
@EnableWebSecurity
public class SecurityConf {

	@Bean
	SecurityFilterChain filterChain(HttpSecurity http, ServerProperties serverProperties, @Value("${permit-all:[]}") String[] permitAll) throws Exception {

		// Configure a resource server with JWT decoder (the customized jwtAuthenticationConverter is picked by Spring Boot)
		http.oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()));

		// State-less session (state in access-token only)
		http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

		// Disable CSRF because of state-less session-management
		http.csrf(csrf -> csrf.disable());

		// Return 401 (unauthorized) instead of 302 (redirect to login) when
		// authorization is missing or invalid
		http.exceptionHandling(eh -> eh.authenticationEntryPoint((request, response, authException) -> {
			response.addHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"Restricted Content\"");
			response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
		}));

		// If SSL enabled, disable http (https only)
		if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
			http.requiresChannel(channel -> channel.anyRequest().requiresSecure());
		}

		// @formatter:off
        http.authorizeHttpRequests(requests -> requests
            .requestMatchers(Stream.of(permitAll).map(AntPathRequestMatcher::new).toArray(AntPathRequestMatcher[]::new)).permitAll()
            .anyRequest().authenticated());
        // @formatter:on

		return http.build();
	}

	/**
	 * An authorities converter using solely realm_access.roles claim as source and doing no transformation (no prefix, case untouched)
	 */
	@Component
	static class KeycloakRealmRolesGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
		@Override
		@SuppressWarnings({ "unchecked" })
		public List<GrantedAuthority> convert(Jwt jwt) {
			final var realmAccess = (Map<String, Object>) jwt.getClaims().getOrDefault("realm_access", Map.of());
			final var realmRoles = (List<String>) realmAccess.getOrDefault("roles", List.of());
			return realmRoles.stream().map(SimpleGrantedAuthority::new).map(GrantedAuthority.class::cast).toList();
		}
	}

	@Bean
	JwtAuthenticationConverter jwtAuthenticationConverter(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
		final var jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
		jwtAuthenticationConverter.setPrincipalClaimName(StandardClaimNames.PREFERRED_USERNAME);
		return jwtAuthenticationConverter;
	}
}
```
With the following properties:
```yaml
permit-all: >
  /users/me,
  /actuator/health/readiness,
  /actuator/health/liveness

spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://localhost:8443/realms/master
```

In addition to being much more verbose than `spring-addons` version, this is also less flexible:
- we map authorities from a single hardcoded claim
- multi-tenant scenraios are not supported (case where we need to accept tokens issued by more than just one OpenID provider)
- adding CORS configuration would be even more verbose

## `spring-cloud-gateway` as OAuth2 BFF

First thing to note is that `spring-cloud-gateway` is a reactive application, and as so, needs reactive Security configuration (`SecurityWebFilterChain` instead of `SecurityFilterChain`).

To act as OAuth2 BFF, `spring-cloud-gateway` can be configured with the `TokenRelay`. This fitler replaces a request session cookie with an `Authorization` header containing a `Bearer` token in session. Of course, this requires the session to contain such tokens and this is where `spring-boot-starter-oauth2-client` jumps in (with `oauth2Login` to acquire the tokens from the authorization server using the `authorization_code` flow).

But we don't need the `TokenRelay` on all routes and we can save the resources required to maintain session on quite a few routes: some requests don't need to be authorized (those used to get UI assets for instance), and some others are not issued by the SPA (requests to actuator for instance).

As a consequence, we'll configure two distinct `SecurityWebFilterChain` beans:
- one containing resource server configuration for routes for which we don't need sessions (with the same features as for the REST API)
- one containing client configuration for routes involved in login & logout, as well as those configured with the `TokenRelay` filter. This filter-chain will satisfy the followin specs:
  * sessions enabled
  * CSRF protection enabled (required because of session based security). As the frontend is a SPA, the CSRF token should be stored in a cookie with `http-only` flag set to false, so that the SPA can read it and return its value as `X-XSRF-TOKEN` header.
  * `oauth2Login` with success and failure redirected to the UI
  * RP-Initiated Logout (the user session should be ended on both the BFF and the authorization server when he logs out)
  * `/login/**` as well as `/oauth2/**` should be accessible to anonymous requests (for `oauth2Login` to work)

As usual when having more than one security filter-chain beans, all will be ordered and all but the one with the lowest precedence will have a `securityMatcher` to define which request it should be used for. In our case, the client filter-chain is defined with `securityMatcher` for the routes involved in login & logout as well as those configured with `TokenRelay` filter, all other requests behing processed by the resource server filter chain.

### Gateway routing configuration
Gateway routing configuration with Spring Boot is very advanced and we can do all we need with properties:
- activate `SaveSession` filter for all routes
- activate `DedupeResponseHeader` filter to remove potential CORS headers duplicates from all routes
- set a redirection from `/` to `/ui/` (for user experience: when pointing a browser to to the gateway, we'l be redirected to the UI)
- route all requests to UI assets to the server hosting it
- route all requests starting with `/bff/v1` to the REST API with two additional filters:
  * `TokenRelay=` to replace the session cookie with an `Authorization` header containing the access token in session
  * `StripPrefix=2` to remove `/bff/v1` from the path before forwarding the request to the greeitng API
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
        - Path=/bff/v1/**
        filters:
        - TokenRelay=
        - StripPrefix=2
      - id: ui
        uri: ${ui-uri}
        predicates:
        - Path=/ui/**
```

### Gateway security with spring-addons
All the Java configuration we need is related to a "hack" related to SPAs and CORS: instead of returning a `3xx` with a redirection to the authorization server to finish the logout process there after we successfuly logged a user out the BFF, we prefer to return a `201` (accepted) with the URI to follow in a `Location` header.

Spring-addons provides with its own `ServerSuccessLogoutHandler` compatible with OpenID Providers following strictly the RP-Initiated Logout standard, as well as with those "almost" following it. As this success-handler is already configurable from properties, we'll reuse it.
```java
@Configuration
public class SecurityConf {

	@Component
	static class AngularLogoutSucessHandler implements ServerLogoutSuccessHandler {
		private final SpringAddonsServerLogoutSuccessHandler delegate;

		public AngularLogoutSucessHandler(LogoutRequestUriBuilder logoutUriBuilder, ReactiveClientRegistrationRepository clientRegistrationRepo) {
			this.delegate = new SpringAddonsServerLogoutSuccessHandler(logoutUriBuilder, clientRegistrationRepo);
		}

		@Override
		public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
			return delegate.onLogoutSuccess(exchange, authentication).then(Mono.fromRunnable(() -> {
				exchange.getExchange().getResponse().setStatusCode(HttpStatus.ACCEPTED);
			}));
		}

	}
}
```
Most Spring Boot properties for OAuth2 clients are used by spring-addons, but there are quite some more properties we can provide to tweek our conf:
```yaml
scheme: http
issuer: https://localhost:8443/realms/master
client-id: spring-addons-confidential
client-secret: change-me
user-name-attribute: preferred_username
gateway-uri: ${scheme}://localhost:${server.port}
greetings-api-uri: ${scheme}://localhost:7084
ui-uri: ${scheme}://localhost:4200

spring:
  security:
    oauth2:
      client:
        provider:
          keycloak:
            issuer-uri: ${issuer}
            user-name-attribute: ${user-name-attribute}
        registration:
          keycloak:
            provider: keycloak
            client-id: ${client-id}
            client-secret: ${client-secret}
            authorization-grant-type: authorization_code
            scope:
            - openid
            - profile
            - email
            - offline_access
            - roles

com:
  c4-soft:
    springaddons:
      oidc:
        ops:
        - iss: ${issuer}
          authorities:
          - path: $.realm_access.roles
          username-claim: ${user-name-attribute}
        client:
          client-uri: ${gateway-uri}
          security-matchers: 
          - /login/**
          - /oauth2/**
          - /logout
          - /bff/**
          permit-all:
          - /login/**
          - /oauth2/**
          - /bff/**
          csrf: cookie-accessible-from-js
          login-path: /ui/
          post-login-redirect-path: /ui/
          post-logout-redirect-path: /ui/
        resourceserver:
          permit-all:
          - /
          - /login-options
          - /ui/**
          - /actuator/health/readiness
          - /actuator/health/liveness
          - /favicon.ico
```

With this properties and both `spring-boot-starter-oauth2-client` and `spring-boot-starter-oauth2-resource-server` on the classpath, spring-addons creates the two filter-chains we need, replacing its default `ServerLogoutSuccessHandler` with the custom one we defined in the Java conf.

### Gateway security with just "official" starters

Of course, we have to defined the two `SecurityWebFilterChain` beans ourselves. Also, we'll have to provide with our own `ServerLogoutSuccessHandler`, without relying on the one provided by spring-addons. Fortunately, in this tutorial, we are using Keycloak wich is fully compliant with RP-Initiated Logout, and Spring Security provides with an `OidcClientInitiatedServerLogoutSuccessHandler` which can be configured with a post-logout URI (to return to our UI).
```java
@Configuration
@EnableWebFluxSecurity
public class SecurityConf {

	/**
	 * <p>
	 * Security filter-chain for resources needing sessions with CSRF protection enabled and CSRF token cookie accessible to Angular
	 * application.
	 * </p>
	 * <p>
	 * It is defined with low order (high precedence) and security-matcher to limit the resources it applies to.
	 * </p>
	 */
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	SecurityWebFilterChain clientFilterCHain(
			ServerHttpSecurity http,
			ServerProperties serverProperties,
			ReactiveClientRegistrationRepository clientRegistrationRepository,
			@Value("${client-security-matchers:[]}") String[] securityMatchers,
			@Value("${client-permit-all:[]}") String[] permitAll,
			@Value("${post-logout-redirect-uri}") String postLogoutRedirectUri) {

		// Apply this filter-chain only to resources needing sessions
		final var clientRoutes =
				Stream.of(securityMatchers).map(PathPatternParserServerWebExchangeMatcher::new).map(ServerWebExchangeMatcher.class::cast).toList();
		http.securityMatcher(new OrServerWebExchangeMatcher(clientRoutes));

		// Set post-login URI to Angular app (login being successful or not)
		http.oauth2Login(login -> {
			login.authenticationSuccessHandler(new RedirectServerAuthenticationSuccessHandler("/ui/"));
			login.authenticationFailureHandler(new RedirectServerAuthenticationFailureHandler("/ui/"));
		});

		// Keycloak fully complies with RP-Initiated Logout
		http.logout(logout -> {
			logout.logoutSuccessHandler(new AngularLogoutSucessHandler(clientRegistrationRepository, postLogoutRedirectUri));
		});

		// Sessions being necessary, configure CSRF protection to work with Angular.
		// Note the csrfCookieWebFilter below which actually attaches the CSRF token cookie to responses
		http.csrf(csrf -> {
			var delegate = new XorServerCsrfTokenRequestAttributeHandler();
			csrf.csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse()).csrfTokenRequestHandler(delegate::handle);
		});

		// If SSL enabled, disable http (https only)
		if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
			http.redirectToHttps(withDefaults());
		}

		// @formatter:off
		http.authorizeExchange(ex -> ex
				.pathMatchers(permitAll).permitAll()
				.anyExchange().authenticated());
		// @formatter:on

		return http.build();
	}

	@Bean
	WebFilter csrfCookieWebFilter() {
		return (exchange, chain) -> {
			exchange.getAttributeOrDefault(CsrfToken.class.getName(), Mono.empty()).subscribe();
			return chain.filter(exchange);
		};
	}

	/**
	 * <p>
	 * Security filter-chain for resources for which sessions are not needed.
	 * </p>
	 * <p>
	 * It is defined with lower precedence (higher order) than the client filter-chain and no security matcher => this one acts as default for
	 * all requests that do not match the client filter-chain secutiy-matcher.
	 * </p>
	 */
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE + 1)
	SecurityWebFilterChain resourceServerFilterCHain(
			ServerHttpSecurity http,
			ServerProperties serverProperties,
			@Value("${resource-server-permit-all:[]}") String[] permitAll) {
		// Enable resource server configuration with JWT decoder
		http.oauth2ResourceServer(resourceServer -> resourceServer.jwt(withDefaults()));

		// State-less session (state in access-token only)
		http.securityContextRepository(NoOpServerSecurityContextRepository.getInstance());

		// Disable CSRF because of state-less session-management
		http.csrf(csrf -> csrf.disable());

		// Return 401 (unauthorized) instead of 302 (redirect to login) when
		// authorization is missing or invalid
		http.exceptionHandling(exceptionHandling -> {
			exceptionHandling.accessDeniedHandler((var exchange, var ex) -> exchange.getPrincipal().flatMap(principal -> {
				var response = exchange.getResponse();
				response.setStatusCode(principal instanceof AnonymousAuthenticationToken ? HttpStatus.UNAUTHORIZED : HttpStatus.FORBIDDEN);
				response.getHeaders().setContentType(MediaType.TEXT_PLAIN);
				var dataBufferFactory = response.bufferFactory();
				var buffer = dataBufferFactory.wrap(ex.getMessage().getBytes(Charset.defaultCharset()));
				return response.writeWith(Mono.just(buffer)).doOnError(error -> DataBufferUtils.release(buffer));
			}));
		});

		// If SSL enabled, disable http (https only)
		if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
			http.redirectToHttps(withDefaults());
		}

		// @formatter:off
		http.authorizeExchange(exchange -> exchange
				.pathMatchers(permitAll).permitAll()
				.anyExchange().authenticated());
		// @formatter:on

		return http.build();
	}

	static class AngularLogoutSucessHandler implements ServerLogoutSuccessHandler {
		private final OidcClientInitiatedServerLogoutSuccessHandler delegate;
		
		public AngularLogoutSucessHandler(ReactiveClientRegistrationRepository clientRegistrationRepository, String postLogoutRedirectUri) {
			this.delegate = new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository);
			this.delegate.setPostLogoutRedirectUri(postLogoutRedirectUri);
		}

		@Override
		public
				Mono<
						Void>
				onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
			return delegate.onLogoutSuccess(exchange, authentication).then(Mono.fromRunnable(() -> {
				exchange.getExchange().getResponse().setStatusCode(HttpStatus.ACCEPTED);
			}));
		}

	}
}
```
```yaml
scheme: http
issuer: https://localhost:8443/realms/master
client-id: spring-addons-confidential
client-secret: change-me
user-name-attribute: preferred_username
gateway-uri: ${scheme}://localhost:${server.port}
greetings-api-uri: ${scheme}://localhost:7084
ui-uri: ${scheme}://localhost:4200

spring:
  security:
    oauth2:
      client:
        provider:
          keycloak:
            issuer-uri: ${issuer}
            user-name-attribute: ${user-name-attribute}
        registration:
          keycloak:
            provider: keycloak
            client-id: ${client-id}
            client-secret: ${client-secret}
            authorization-grant-type: authorization_code
            scope:
            - openid
            - profile
            - email
            - offline_access
            - roles
      resourceserver:
        jwt:
          issuer-uri: ${issuer}
```

## GatewayController
The last piece we need on our BFF is a controller exposing login options it accepts. For that, we can iterate over OAuth2 client registrations, filter those configured with `authorization_code` flow, extract the login URI and return it as a JSON payload.

For implementation details, refer to `GatewayController.java`.