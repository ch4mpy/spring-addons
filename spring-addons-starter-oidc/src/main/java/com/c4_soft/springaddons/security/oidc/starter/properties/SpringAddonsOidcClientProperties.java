package com.c4_soft.springaddons.security.oidc.starter.properties;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import lombok.Data;

/**
 * Auto-configuration for an OAuth2 client (secured with session, not access token)
 * Security(Web)FilterChain with &#64;Order(Ordered.LOWEST_PRECEDENCE - 1). Typical use-cases are
 * spring-cloud-gateway used as BFF and applications with Thymeleaf or another server-side rendering
 * framework. Default configuration includes: enabled sessions, CSRF protection, "oauth2Login",
 * "logout". securityMatchers must be set for this filter-chain &#64;Bean and its dependencies to be
 * defined. <b>Properties defined here are a complement for spring.security.oauth2.client.*</b>
 * (which are required when enabling spring-addons client filter-chain).
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Data
public class SpringAddonsOidcClientProperties {
  public static final String RESPONSE_STATUS_HEADER = "X-RESPONSE-STATUS";

  public static final String POST_AUTHENTICATION_SUCCESS_URI_HEADER = "X-POST-LOGIN-SUCCESS-URI";
  public static final String POST_AUTHENTICATION_SUCCESS_URI_PARAM = "post_login_success_uri";
  public static final String POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE =
      POST_AUTHENTICATION_SUCCESS_URI_PARAM;

  public static final String POST_AUTHENTICATION_FAILURE_URI_HEADER = "X-POST-LOGIN-FAILURE-URI";
  public static final String POST_AUTHENTICATION_FAILURE_URI_PARAM = "post_login_failure_uri";
  public static final String POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE =
      POST_AUTHENTICATION_FAILURE_URI_PARAM;
  public static final String POST_AUTHENTICATION_FAILURE_CAUSE_ATTRIBUTE = "error";

  public static final String POST_LOGOUT_SUCCESS_URI_HEADER = "X-POST-LOGOUT-SUCCESS-URI";
  public static final String POST_LOGOUT_SUCCESS_URI_PARAM = "post_logout_success_uri";

  /**
   * Path matchers for the routes secured with the auto-configured client filter-chain. If left
   * empty, OAuth2 client auto-configuration is disabled. It should include "/login/**" and
   * "/oauth2/**" for login process. Can be set to "/**" to intercept all requests (OAuth2 client
   * only application, no REST API secured with access tokens).
   */
  private List<String> securityMatchers = List.of();

  /**
   * Fully qualified URI of the configured OAuth2 client.
   */
  private URI clientUri = URI.create("/");

  /**
   * URI at which a login can be performed. If left empty, ${client-uri}/login is used. Can be
   * changed to the URI on a SPA or a mobile application deep-link
   */
  private Optional<URI> loginUri = Optional.empty();

  /**
   * URI containing scheme, host and port where the user should be redirected after a successful
   * login (defaults to the client URI)
   */
  private Optional<URI> postLoginRedirectHost = Optional.empty();

  /**
   * Where to redirect the user after successful login
   */
  private Optional<String> postLoginRedirectPath = Optional.empty();

  /**
   * Where to redirect the user after login failure
   */
  private Optional<URI> loginErrorRedirectPath = Optional.empty();

  /**
   * Handling of invalid <b>servlet</b> sessions. The default behavior is to create a new
   * (anonymous) session and to redirect to the same URI for a retry.
   */
  private InvalidSessionProperties invalidSession = new InvalidSessionProperties();

  /**
   * HTTP status for redirections in OAuth2 login and logout. You might set this to something in 2xx
   * range (like OK, ACCEPTED, NO_CONTENT, ...) for single page and mobile applications to handle
   * this redirection as it wishes (change the user-agent, clear some headers, ...).
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
   * URI containing scheme, host and port where the user should be redirected after a successful
   * logout (defaults to the client URI)
   */
  private Optional<URI> postLogoutRedirectHost = Optional.empty();

  /**
   * Path (relative to clientUri) where the user should be redirected after being logged out from
   * authorization server(s)
   */
  private Optional<String> postLogoutRedirectPath = Optional.empty();

  public URI getPostLogoutRedirectHost() {
    return postLogoutRedirectHost.orElse(clientUri);
  }

  public URI getPostLogoutRedirectUri() {
    var uri = UriComponentsBuilder.fromUri(getPostLogoutRedirectHost());
    postLogoutRedirectPath.ifPresent(uri::path);

    return uri.build(Map.of());
  }

  /**
   * Map of logout properties indexed by client registration ID (must match a registration in Spring
   * Boot OAuth2 client configuration). {@link OAuth2LogoutProperties} are configuration for
   * authorization server not strictly following the
   * <a href= "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated Logout</a>
   * standard, but exposing a logout end-point expecting an authorized GET request with following
   * request params:
   * <ul>
   * <li>"client-id" (required)</li>
   * <li>post-logout redirect URI (optional)</li>
   * </ul>
   */
  private Map<String, OAuth2LogoutProperties> oauth2Logout = new HashMap<>();

  /**
   * <p>
   * If true, AOP is used to instrument authorized client repository and keep the principalName
   * current user has for each issuer he authenticates on.
   * </p>
   * <p>
   * This is useful only if you allow a user to authenticate on more than one OpenID Provider at a
   * time. For instance, user logs in on Google and on an authorization server of your own and your
   * client sends direct queries to Google APIs (with an access token issued by Google) and resource
   * servers of your own (with an access token from your authorization server).
   * </p>
   */
  private boolean multiTenancyEnabled = false;

  /**
   * Path matchers for the routes accessible to anonymous requests
   */
  private List<String> permitAll = List.of("/login/**", "/oauth2/**");

  /**
   * CSRF protection configuration for the auto-configured client filter-chain
   */
  private Csrf csrf = Csrf.DEFAULT;

  /**
   * When true, PKCE is enabled (by default, Spring enables it only for "public" clients)
   */
  private boolean pkceForced = false;

  /**
   * Fine grained CORS configuration
   * 
   * @deprecated use com.c4-soft.springaddons.oidc.cors instead
   */
  @Deprecated(forRemoval = true)
  private List<CorsProperties> cors = List.of();

  /**
   * Additional parameters to send with authorization request, mapped by client registration IDs
   * 
   * @deprecated use the more concise authorization-params syntax
   */
  @Deprecated
  private Map<String, List<RequestParam>> authorizationRequestParams = new HashMap<>();

  /**
   * <p>
   * Additional parameters to send with authorization request, mapped by client registration IDs.
   * </p>
   * <p>
   * {@link OAuth2AuthorizationRequest#getAdditionalParameters()} return a Map&lt;String,
   * Object&gt;, when it should probably be Map&lt;String, List&lt;String&gt;&gt;. Also the
   * serializer does not handle collections correctly (serializes using {@link Object#toString()}
   * instead of repeating the parameter with each value toString()). What spring-addons does is
   * joining the String values with a comma.
   * </p>
   */
  private Map<String, Map<String, List<String>>> authorizationParams = new HashMap<>();

  public MultiValueMap<String, String> getExtraAuthorizationParameters(String registrationId) {
    return getExtraParameters(registrationId, authorizationRequestParams, authorizationParams);
  }

  /**
   * Additional parameters to send with token request, mapped by client registration IDs
   * 
   * @deprecated use the more concise token-params syntax
   */
  @Deprecated
  private Map<String, List<RequestParam>> tokenRequestParams = new HashMap<>();

  /**
   * Additional parameters to send with authorization request, mapped by client registration IDs
   */
  private Map<String, Map<String, List<String>>> tokenParams = new HashMap<>();

  public MultiValueMap<String, String> getExtraTokenParameters(String registrationId) {
    return getExtraParameters(registrationId, tokenRequestParams, tokenParams);
  }

  private static MultiValueMap<String, String> getExtraParameters(String registrationId,
      Map<String, List<RequestParam>> requestParams,
      Map<String, Map<String, List<String>>> requestParamsMap) {
    final var extraParameters = Optional.ofNullable(requestParamsMap.get(registrationId))
        .map(LinkedMultiValueMap::new).orElse(new LinkedMultiValueMap<>());
    for (final var param : requestParams.getOrDefault(registrationId, List.of())) {
      if (StringUtils.hasText(param.getName())) {
        extraParameters.add(param.getName(), param.getValue());
      }
    }
    return extraParameters;
  }

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
     * request param name for post-logout redirect URI (where the user should be redirected after
     * his session is closed on the authorization server)
     */
    private Optional<String> postLogoutUriRequestParam = Optional.empty();

    /**
     * request param name for setting an ID-Token hint
     */
    private Optional<String> idTokenHintRequestParam = Optional.empty();

    /**
     * RP-Initiated Logout is enabled by default. Setting this to false disables it.
     */
    private boolean enabled = true;
  }

  private BackChannelLogoutProperties backChannelLogout = new BackChannelLogoutProperties();

  @Data
  public static class BackChannelLogoutProperties {
    private boolean enabled = false;

    /**
     * The URI for a loop of the Spring client to itself in which it actually ends the user session.
     * Overriding this can be useful to force the scheme and port in the case where the client is
     * behind a reverse proxy with different scheme and port (default URI uses the original
     * Back-Channel Logout request scheme and ports).
     */
    private Optional<String> internalLogoutUri = Optional.empty();

    private Optional<String> cookieName = Optional.empty();
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
  public static class InvalidSessionProperties {

    /**
     * Location header in case of an invalid session. If left empty, the request URI is used.
     */
    private Optional<URI> location = Optional.empty();

    /**
     * Status for the response after a new (anonymous) session is created. The default is a
     * redirection. So, if the path property is left empty, this will trigger a retry of the request
     * with an anonymous, but valid, session.
     */
    private HttpStatus status = HttpStatus.FOUND;
  }

  @Data
  public static class OAuth2RedirectionProperties {
    /**
     * Defines {@link AuthenticationEntryPoint} or {@link ServerAuthenticationEntryPoint} behavior
     */
    private HttpStatus authenticationEntryPoint = HttpStatus.FOUND;

    /**
     * Status for the 1st response in authorization code flow, with location to get authorization
     * code from authorization server
     */
    private HttpStatus preAuthorizationCode = HttpStatus.FOUND;

    /**
     * Status for the response after authorization code, with location to the UI
     */
    private HttpStatus postAuthorizationCode = HttpStatus.FOUND;

    /**
     * Status for the response after an authorization failure
     */
    private HttpStatus postAuthorizationFailure = HttpStatus.FOUND;

    /**
     * Status for the response after BFF logout, with location to authorization server logout
     * endpoint
     */
    private HttpStatus rpInitiatedLogout = HttpStatus.FOUND;
  }

  public Optional<OAuth2LogoutProperties> getLogoutProperties(String clientRegistrationId) {
    return Optional.ofNullable(oauth2Logout.get(clientRegistrationId));
  }
}
