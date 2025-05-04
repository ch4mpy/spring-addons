package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import com.c4_soft.springaddons.security.oidc.starter.AdditionalParamsAuthorizationRequestCustomizer;
import com.c4_soft.springaddons.security.oidc.starter.CompositeOAuth2AuthorizationRequestCustomizer;
import com.c4_soft.springaddons.security.oidc.starter.properties.InvalidRedirectionUriException;
import com.c4_soft.springaddons.security.oidc.starter.properties.MisconfiguredPostLoginUriException;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Support three features:
 * <ul>
 * <li>Use the {@link SpringAddonsOidcClientProperties#clientUri
 * SpringAddonsOidcClientProperties#client-uri} to set the base URI of authorization-code callback
 * (of interest for instance when using an ingress or another gateway in front of the OAuth2 client
 * with oauth2Login)</li>
 * <li>Defining authorization request additional parameters from properties (like audience for
 * Auth0)</li>
 * <li>Save in session post-login URIs provided as header
 * ({@link SpringAddonsOidcClientProperties#POST_AUTHENTICATION_SUCCESS_URI_HEADER} and
 * {@link SpringAddonsOidcClientProperties#POST_AUTHENTICATION_FAILURE_URI_HEADER}) or request param
 * ({@link SpringAddonsOidcClientProperties#POST_AUTHENTICATION_SUCCESS_URI_PARAM} and
 * {@link SpringAddonsOidcClientProperties#POST_AUTHENTICATION_FAILURE_URI_PARAM}). If both are
 * provided, header wins. The key used in session are
 * {@link SpringAddonsOidcClientProperties#POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE} and
 * {@link SpringAddonsOidcClientProperties#POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE}</li>
 * </ul>
 * The post-login URIs are used by the default {@link AuthenticationSuccessHandler} and
 * {@link AuthenticationFailureHandler}
 * <p>
 * When needing fancy request customizers (for instance to add parameters with name or value
 * computed at runtime), you may extend this class and override
 * {@link SpringAddonsOAuth2AuthorizationRequestResolver#getOAuth2AuthorizationRequestCustomizer(HttpServletRequest, String)}
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see SpringAddonsOidcClientProperties for header and request parameter constants definitions
 * @see SpringAddonsOauth2AuthenticationSuccessHandler
 * @see SpringAddonsOauth2AuthenticationFailureHandler
 */
public class SpringAddonsOAuth2AuthorizationRequestResolver
    implements OAuth2AuthorizationRequestResolver {
  private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";

  private final URI clientUri;
  private final Map<String, CompositeOAuth2AuthorizationRequestCustomizer> requestCustomizers;
  private final ClientRegistrationRepository clientRegistrationRepository;
  private final AntPathRequestMatcher authorizationRequestMatcher = new AntPathRequestMatcher(
      OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI + "/{"
          + REGISTRATION_ID_URI_VARIABLE_NAME + "}");
  private final List<Pattern> postLoginAllowedUriPatterns;

  public SpringAddonsOAuth2AuthorizationRequestResolver(OAuth2ClientProperties bootClientProperties,
      ClientRegistrationRepository clientRegistrationRepository,
      SpringAddonsOidcClientProperties addonsClientProperties) {

    this.postLoginAllowedUriPatterns = addonsClientProperties.getPostLoginAllowedUriPatterns();
    final var postLoginRedirectUriString =
        addonsClientProperties.getPostLoginRedirectUri().toString();
    if (postLoginAllowedUriPatterns.stream()
        .noneMatch(p -> p.matcher(postLoginRedirectUriString).matches())) {
      throw new MisconfiguredPostLoginUriException(URI.create(postLoginRedirectUriString),
          postLoginAllowedUriPatterns);
    }

    this.clientUri = addonsClientProperties.getClientUri();

    this.requestCustomizers = bootClientProperties.getRegistration().entrySet().stream()
        .collect(Collectors.toMap(Map.Entry::getKey, registrationEntry -> {
          final var additionalProperties =
              addonsClientProperties.getExtraAuthorizationParameters(registrationEntry.getKey());

          final var customizers = additionalProperties.size() > 0
              ? new AdditionalParamsAuthorizationRequestCustomizer[] {
                  new AdditionalParamsAuthorizationRequestCustomizer(additionalProperties)}
              : new AdditionalParamsAuthorizationRequestCustomizer[] {};

          final var requestCustomizer =
              new CompositeOAuth2AuthorizationRequestCustomizer(customizers);

          if (addonsClientProperties.isPkceForced()) {
            requestCustomizer.addCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
          }

          return requestCustomizer;
        }));

    this.clientRegistrationRepository = clientRegistrationRepository;
  }

  private Optional<String> getFirstParam(HttpServletRequest request, String paramName) {
    final var values = request.getParameterValues(paramName);
    if (values == null || values.length < 1) {
      return Optional.empty();
    }
    return Optional.of(values[0]);
  }

  private void savePostLoginUrisInSession(HttpServletRequest request) {
    final var session = request.getSession();
    Optional
        .ofNullable(Optional
            .ofNullable(request
                .getHeader(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER))
            .orElse(getFirstParam(request,
                SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_PARAM)
                    .orElse(null)))
        .filter(StringUtils::hasText).map(URI::create).ifPresent(postLoginSuccessUri -> {
          final var postLoginSuccessUriString = postLoginSuccessUri.toString();
          if (postLoginAllowedUriPatterns.stream()
              .noneMatch(p -> p.matcher(postLoginSuccessUriString).matches())) {
            throw new InvalidRedirectionUriException(postLoginSuccessUri);
          }
          session.setAttribute(
              SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE,
              postLoginSuccessUri);
        });

    Optional
        .ofNullable(Optional
            .ofNullable(request
                .getHeader(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_HEADER))
            .orElse(getFirstParam(request,
                SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_PARAM)
                    .orElse(null)))
        .filter(StringUtils::hasText).map(URI::create).ifPresent(postLoginFailureUri -> {
          final var postLoginFailureUriString = postLoginFailureUri.toString();
          if (postLoginAllowedUriPatterns.stream()
              .noneMatch(p -> p.matcher(postLoginFailureUriString).matches())) {
            throw new InvalidRedirectionUriException(postLoginFailureUri);
          }
          session.setAttribute(
              SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE,
              postLoginFailureUri);
        });
  }

  @Override
  public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
    savePostLoginUrisInSession(request);
    final var clientRegistrationId = resolveRegistrationId(request);

    final var delegate = getRequestResolver(request, clientRegistrationId);
    if (delegate == null) {
      return null;
    }

    final var resolved = delegate.resolve(request);
    final var absolute = toAbsolute(resolved, request);
    return absolute;
  }

  @Override
  public OAuth2AuthorizationRequest resolve(HttpServletRequest request,
      String clientRegistrationId) {
    savePostLoginUrisInSession(request);

    final var delegate = getRequestResolver(request, clientRegistrationId);
    if (delegate == null) {
      return null;
    }

    final var resolved = delegate.resolve(request, clientRegistrationId);
    final var absolute = toAbsolute(resolved, request);
    return absolute;
  }

  /**
   * You probably don't need to override this. See getOAuth2AuthorizationRequestCustomizer to add
   * advanced request customizer(s)
   * 
   * @param request
   * @param clientRegistrationId
   * @return
   */
  protected OAuth2AuthorizationRequestResolver getRequestResolver(HttpServletRequest request,
      String clientRegistrationId) {
    final var requestCustomizer =
        getOAuth2AuthorizationRequestCustomizer(request, clientRegistrationId);
    if (requestCustomizer == null) {
      return null;
    }

    final var delegate = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository,
        OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
    delegate.setAuthorizationRequestCustomizer(requestCustomizer);

    return delegate;
  }

  /**
   * Override this to use a "dynamic" request customizer. Something like:
   * 
   * <pre>
   * return new CompositeOAuth2AuthorizationRequestCustomizer(getCompositeOAuth2AuthorizationRequestCustomizer(clientRegistrationId), new MyDynamicCustomizer(request), ...);
   * </pre>
   * 
   * @return
   */
  protected Consumer<OAuth2AuthorizationRequest.Builder> getOAuth2AuthorizationRequestCustomizer(
      HttpServletRequest request, String clientRegistrationId) {
    return getCompositeOAuth2AuthorizationRequestCustomizer(clientRegistrationId);
  }

  /**
   * @return a request customizer adding PKCE token (if activated) and "static" parameters defined
   *         in spring-addons properties
   */
  protected CompositeOAuth2AuthorizationRequestCustomizer getCompositeOAuth2AuthorizationRequestCustomizer(
      String clientRegistrationId) {
    return this.requestCustomizers.get(clientRegistrationId);
  }

  private OAuth2AuthorizationRequest toAbsolute(
      OAuth2AuthorizationRequest defaultAuthorizationRequest, HttpServletRequest request) {
    if (defaultAuthorizationRequest == null || clientUri == null) {
      return defaultAuthorizationRequest;
    }

    final var original = URI.create(defaultAuthorizationRequest.getRedirectUri());
    final var redirectUri = UriComponentsBuilder.fromUri(clientUri).path(original.getPath())
        .query(original.getQuery()).fragment(original.getFragment()).build().toString();

    return OAuth2AuthorizationRequest.from(defaultAuthorizationRequest).redirectUri(redirectUri)
        .build();
  }

  private String resolveRegistrationId(HttpServletRequest request) {
    if (this.authorizationRequestMatcher.matches(request)) {
      return this.authorizationRequestMatcher.matcher(request).getVariables()
          .get(REGISTRATION_ID_URI_VARIABLE_NAME);
    }
    return null;
  }
}
