package com.c4_soft.springaddons.security.oidc.starter.properties;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.web.util.UriComponentsBuilder;

import lombok.Data;

/**
 * Auto-configuration for an OAuth2 client (secured with session, not access token) Security(Web)FilterChain with &#64;Order(Ordered.LOWEST_PRECEDENCE - 1).
 * Typical use-cases are spring-cloud-gateway used as BFF and applications with Thymeleaf or another server-side rendering framework. Default configuration
 * includes: enabled sessions, CSRF protection, "oauth2Login", "logout". securityMatchers must be set for this filter-chain &#64;Bean and its dependencies to be
 * defined. <b>Properties defined here are a complement for spring.security.oauth2.client.*</b> (which are required when enabling spring-addons client
 * filter-chain).
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Data
public class SpringAddonsOidcClientProperties {

	/**
	 * Path matchers for the routes secured with the auto-configured client filter-chain. If left empty, OAuth2 client auto-configuration is disabled. It should
	 * include "/login/**" and "/oauth2/**" for login process. Can be set to "/**" to intercept all requests (OAuth2 client only application, no REST API
	 * secured with access tokens).
	 */
	private String[] securityMatchers = {};

	/**
	 * Fully qualified URI of the configured OAuth2 client.
	 */
	private URI clientUri = URI.create("/");

	/**
	 * Path to the login page. Provide one only in the following cases:
	 * <ul>
	 * <li>you want to provide your own login &#64;Controller</li>
	 * <li>you want to use port 80 or 8080 with SSL enabled (this will require you to provide with the login &#64;Controller above)</li>
	 * </ul>
	 * If left empty, the default Spring Boot configuration for OAuth2 login is applied
	 */
	private Optional<String> loginPath = Optional.empty();

	/**
	 * URI containing scheme, host and port where the user should be redirected after a successful login (defaults to the client URI)
	 */
	private Optional<URI> postLoginRedirectHost = Optional.empty();

	/**
	 * Where to redirect the user after successful login
	 */
	private Optional<String> postLoginRedirectPath = Optional.empty();

	/**
	 * HTTP status for redirections in OAuth2 login and logout. You might set this to something in 2xx range (like OK, ACCEPTED, NO_CONTENT, ...) for single
	 * page and mobile applications to handle this redirection as it wishes (change the user-agent, clear some headers, ...).
	 */
	private OAuth2RedirectionProperties oauth2Redirections = new OAuth2RedirectionProperties();

	public URI getPostLoginRedirectHost() {
		return postLoginRedirectHost.orElse(clientUri);
	}

	public Optional<URI> getPostLoginRedirectUri() {
		if (postLoginRedirectHost.isEmpty() && postLoginRedirectPath.isEmpty()) {
			return Optional.empty();
		}
		final var uri = UriComponentsBuilder.fromUri(getPostLoginRedirectHost());
		postLoginRedirectPath.ifPresent(uri::path);

		return Optional.of(uri.build(Map.of()));
	}

	/**
	 * URI containing scheme, host and port where the user should be redirected after a successful logout (defaults to the client URI)
	 */
	private Optional<URI> postLogoutRedirectHost = Optional.empty();

	/**
	 * Path (relative to clientUri) where the user should be redirected after being logged out from authorization server(s)
	 */
	private Optional<String> postLogoutRedirectPath;

	public URI getPostLogoutRedirectHost() {
		return postLogoutRedirectHost.orElse(clientUri);
	}

	public URI getPostLogoutRedirectUri() {
		final var uri = UriComponentsBuilder.fromUri(getPostLogoutRedirectHost());
		postLogoutRedirectPath.ifPresent(uri::path);

		return uri.build(Map.of());
	}

	/**
	 * Map of logout properties indexed by client registration ID (must match a registration in Spring Boot OAuth2 client configuration).
	 * {@link OAuth2LogoutProperties} are configuration for authorization server not strictly following the
	 * <a href= "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated Logout</a> standard, but exposing a logout end-point expecting an
	 * authorized GET request with following request params:
	 * <ul>
	 * <li>"client-id" (required)</li>
	 * <li>post-logout redirect URI (optional)</li>
	 * </ul>
	 */
	private Map<String, OAuth2LogoutProperties> oauth2Logout = new HashMap<>();

	/**
	 * <p>
	 * If true, AOP is used to instrument authorized client repository and keep the principalName current user has for each issuer he authenticates on.
	 * </p>
	 * <p>
	 * This is useful only if you allow a user to authenticate on more than one OpenID Provider at a time. For instance, user logs in on Google and on an
	 * authorization server of your own and your client sends direct queries to Google APIs (with an access token issued by Google) and resource servers of your
	 * own (with an access token from your authorization server).
	 * </p>
	 */
	private boolean multiTenancyEnabled = false;

	/**
	 * Whether to enable a security filter-chain and a controller (intercepting POST requests to "/backchannel_logout") to implement the client side of a
	 * <a href="https://openid.net/specs/openid-connect-backchannel-1_0.html">Back-Channel Logout</a>
	 */
	// private boolean backChannelLogoutEnabled = false;

	/**
	 * Path matchers for the routes accessible to anonymous requests
	 */
	private String[] permitAll = { "/login/**", "/oauth2/**" };

	/**
	 * CSRF protection configuration for the auto-configured client filter-chain
	 */
	private Csrf csrf = Csrf.DEFAULT;

	/**
	 * Fine grained CORS configuration
	 */
	private CorsProperties[] cors = {};

	/**
	 * Additional parameters to send with authorization-code request, mapped by client registration IDs
	 */
	private Map<String, RequestParam[]> authorizationRequestParams = new HashMap<>();

	/**
	 * Logout properties for OpenID Providers which do not implement the RP-Initiated Logout spec
	 *
	 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
	 */
	@Data
	public static class OAuth2LogoutProperties {

		/**
		 * URI on the authorization server where to redirect the user for logout
		 */
		private URI uri;

		/**
		 * request param name for client-id
		 */
		private Optional<String> clientIdRequestParam = Optional.empty();

		/**
		 * request param name for post-logout redirect URI (where the user should be redirected after his session is closed on the authorization server)
		 */
		private Optional<String> postLogoutUriRequestParam = Optional.empty();

		/**
		 * request param name for setting an ID-Token hint
		 */
		private Optional<String> idTokenHintRequestParam = Optional.empty();
	}

	/**
	 * Request parameter
	 *
	 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
	 */
	@Data
	public static class RequestParam {
		/**
		 * request parameter name
		 */
		private String name;

		/**
		 * request parameter value
		 */
		private String value;
	}

	@Data
	public static class OAuth2RedirectionProperties {

		/**
		 * Status for the 1st response in authorization code flow, with location to get authorization code from authorization server
		 */
		private HttpStatus preAuthorizationCode = HttpStatus.FOUND;

		/**
		 * Status for the response after authorization code, with location to the UI
		 */
		private HttpStatus postAuthorizationCode = HttpStatus.FOUND;

		/**
		 * Status for the response after BFF logout, with location to authorization server logout endpoint
		 */
		private HttpStatus rpInitiatedLogout = HttpStatus.FOUND;
	}

	public Optional<OAuth2LogoutProperties> getLogoutProperties(String clientRegistrationId) {
		return Optional.ofNullable(oauth2Logout.get(clientRegistrationId));
	}
}