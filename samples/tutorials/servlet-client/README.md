# Servlet Application
In this tutorial, we'll configure a servlet (WebMVC) application as an OAuth2 client and then have it query a REST API.

## 1. Project Initialization
As usual, we'll start with http://start.spring.io/ adding the following dependencies:
- Spring Web
- OAuth2 Client
- Spring Boot Actuator
- Lombok
- Spring Boot DevTools
- GraalVM Native Support

Once the project unpacked, replace the `src/main/resources/application.properties` with the following `src/main/resources/application.yaml`:
```yaml
scheme: http
keycloak-port: 8442
keycloak-issuer: ${scheme}://localhost:${keycloak-port}/realms/master
keycloak-secret: change-me
cognito-issuer: https://cognito-idp.us-west-2.amazonaws.com/us-west-2_RzhmgLwjl
cognito-secret: change-me
auth0-issuer: https://dev-ch4mpy.eu.auth0.com/
autho-secret: change-me

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
            client-name: a local Keycloak instance
            client-id: spring-addons-confidential
            client-secret: ${keycloak-secret}
            provider: keycloak
            scope: openid,profile,email,offline_access
          cognito-confidential-user:
            authorization-grant-type: authorization_code
            client-name: Amazon Cognito
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
We'll also need a static `src/main/resources/static/index.html` page to have something to see once we're authenticated:
```html
<!DOCTYPE HTML>
<html>

<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
	<meta name="description" content="">
	<meta name="author" content="">
	<title>Reactive Application</title>
	<link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M" crossorigin="anonymous">
	<link href="https://getbootstrap.com/docs/4.0/examples/signin/signin.css" rel="stylesheet" crossorigin="anonymous"/>
</head>

<body>
<div class="container">
	<h1 class="form-signin-heading">Static Index</h1>
	<a href="/login"><button type="button">Login</button></a>
	<a href="/logout"><button type="button">Logout</button></a>
</div>
</body>
```
We can now run the app and browse to http://localhost:7443.

At first glance, things to be working: we can login on any of the configured OIDC Providers:
- before login, we can't access index and are redirect to login instead
- after login on any of the configured, we can access the index
- after logout, we can't access the index anymore

But with a little more testing, we face a first issue: if we login again on an OIDC Providers we were already identified, then we are not prompted for our credentials (login happens silently). To solve that, we'll have to configure [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) so that the session on the OP is invalidated too when we logout a user from our client.

## 2. RP-Initiated Logout
Let's get our hands on the web security configuration and define a security filter-chain by ourselves

### 2.1. Standard RP-Initiated Logout
Spring provides with a `LogoutSuccessHandler` for OIDC Providers implementing the RP-Initiated Logout: `OidcClientInitiatedLogoutSuccessHandler`
```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class WebSecurityConfig {
	@Bean
	SecurityFilterChain clientSecurityFilterChain(HttpSecurity http, ClientRegistrationRepository clientRegistrationRepo) throws Exception {
		http.oauth2Login();
		http.logout(logout -> {
			final var handler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepo);
			handler.setPostLogoutRedirectUri("{baseUrl}");
			logout.logoutSuccessHandler(handler);
		});
		http.authorizeHttpRequests(ex -> ex.requestMatchers("/login/**", "/oauth2/**").permitAll().anyRequest().authenticated());
		return http.build();
	}
}
```
Great! Logout now works as expected with Keycloak, but it's another story with Auth0 and Cognito which diverge from the standard: the `end_session_endpoint` is not listed in `.well-known/openid-configuration` and the parameter name for `post_logout_redirect_uri` is not standard.

### 2.2. Non-Standard RP-Initiated Logout
Let's write our own `LogoutSuccessHandler` to specify the logout URI as well as parameter name for post-logout URI.

For that, let's first declare configuration properties:
```java
@Data
@Configuration
@ConfigurationProperties(prefix = "logout")
static class LogoutProperties {
	private Map<String, ProviderLogoutProperties> registration = new HashMap<>();

	@Data
	static class ProviderLogoutProperties {
		private URI logoutUri;
		private String postLogoutUriParameterName;
	}
}
```
Adding those properties to the yaml (mind the provider IDs which must be the same as those under `spring.security.oauth2.client.registration`):
```yaml
logout:
  registration:
    cognito-confidential-user:
      logout-uri: https://spring-addons.auth.us-west-2.amazoncognito.com/logout
      post-logout-uri-parameter-name: logout_uri
    auth0-confidential-user:
      logout-uri: ${auth0-issuer}v2/logout
      post-logout-uri-parameter-name: returnTo
```
Now, we can define a logout success handler parsing this configuration for non standard RP-Initiated Logout (taking "inspiration" from the `OidcClientInitiatedLogoutSuccessHandler`:
```java
@RequiredArgsConstructor
static class AlmostOidcClientInitiatedLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {
	private final LogoutProperties.ProviderLogoutProperties properties;
	private final ClientRegistration clientRegistration;
	private final String postLogoutRedirectUri;

	@Override
	protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		if (authentication instanceof OAuth2AuthenticationToken oauthentication && authentication.getPrincipal() instanceof OidcUser oidcUser) {
			final var endSessionUri = UriComponentsBuilder.fromUri(properties.getLogoutUri()).queryParam("client_id", clientRegistration.getClientId())
					.queryParam("id_token_hint", oidcUser.getIdToken().getTokenValue())
					.queryParam(properties.getPostLogoutUriParameterName(), postLogoutRedirectUri(request).toString()).toUriString();
			return endSessionUri.toString();
		}
		return super.determineTargetUrl(request, response, authentication);
	}

	private String postLogoutRedirectUri(HttpServletRequest request) {
		if (this.postLogoutRedirectUri == null) {
			return null;
		}
		// @formatter:off
		UriComponents uriComponents = UriComponentsBuilder.fromUriString(request.getRequestURL().toString())
				.replacePath(request.getContextPath())
				.replaceQuery(null)
				.fragment(null)
				.build();

		Map<String, String> uriVariables = new HashMap<>();
		String scheme = uriComponents.getScheme();
		uriVariables.put("baseScheme", (scheme != null) ? scheme : "");
		uriVariables.put("baseUrl", uriComponents.toUriString());

		String host = uriComponents.getHost();
		uriVariables.put("baseHost", (host != null) ? host : "");

		String path = uriComponents.getPath();
		uriVariables.put("basePath", (path != null) ? path : "");

		int port = uriComponents.getPort();
		uriVariables.put("basePort", (port == -1) ? "" : ":" + port);

		uriVariables.put("registrationId", clientRegistration.getRegistrationId());

		return UriComponentsBuilder.fromUriString(this.postLogoutRedirectUri)
				.buildAndExpand(uriVariables)
				.toUriString();
		// @formatter:on
	}
}
```
This handler is fine for non-standard OPs, but if want to keep Spring's logout success handler for Keycloak (and avoid defining logout properties for it), we need a facade for the two implementations we now have:
```java
@RequiredArgsConstructor
static class DelegatingOidcClientInitiatedLogoutSuccessHandler implements LogoutSuccessHandler {
	private final Map<String, LogoutSuccessHandler> delegates;

	public DelegatingOidcClientInitiatedLogoutSuccessHandler(
			InMemoryClientRegistrationRepository clientRegistrationRepository,
			LogoutProperties properties,
			String postLogoutRedirectUri) {
		delegates = StreamSupport.stream(clientRegistrationRepository.spliterator(), false)
				.collect(Collectors.toMap(ClientRegistration::getRegistrationId, clientRegistration -> {
					final var registrationProperties = properties.getRegistration().get(clientRegistration.getRegistrationId());
					if (registrationProperties == null) {
						final var handler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
						handler.setPostLogoutRedirectUri(postLogoutRedirectUri);
						return handler;
					}
					return new AlmostOidcClientInitiatedLogoutSuccessHandler(registrationProperties, clientRegistration, postLogoutRedirectUri);
				}));
	}

	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
			throws IOException,
			ServletException {
		if (authentication instanceof OAuth2AuthenticationToken oauthentication && authentication.getPrincipal() instanceof OidcUser oidcUser) {
			delegates.get(oauthentication.getAuthorizedClientRegistrationId()).onLogoutSuccess(request, response, authentication);
		}
	}

}
```
This handler switches between Spring's `OidcClientInitiatedLogoutSuccessHandler` and our `AlmostOidcClientInitiatedLogoutSuccessHandler` depending on the configuration properties.

Last we need to update the security filter-chain to use the new `DelegatingOidcClientInitiatedServerLogoutSuccessHandler`:
```java
@Bean
SecurityFilterChain
		clientSecurityFilterChain(HttpSecurity http, InMemoryClientRegistrationRepository clientRegistrationRepository, LogoutProperties logoutProperties)
				throws Exception {
	http.oauth2Login();
	http.logout(logout -> {
		logout.logoutSuccessHandler(new DelegatingOidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository, logoutProperties, "{baseUrl}"));
	});
	http.authorizeHttpRequests(ex -> ex.requestMatchers("/login/**", "/oauth2/**").permitAll().anyRequest().authenticated());
	return http.build();
}
```