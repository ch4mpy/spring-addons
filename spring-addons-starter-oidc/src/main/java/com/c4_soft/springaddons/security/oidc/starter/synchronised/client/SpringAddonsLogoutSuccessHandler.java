package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.util.StringUtils;
import com.c4_soft.springaddons.security.oidc.starter.LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oidc.starter.SpringAddonsOAuth2LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oidc.starter.properties.InvalidRedirectionUriException;
import com.c4_soft.springaddons.security.oidc.starter.properties.MisconfiguredPostLogoutUriException;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.EqualsAndHashCode;

/**
 * <p>
 * Provide with <a href= "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated
 * Logout</a> for authorization-servers fully compliant with OIDC standard as well as those "almost"
 * implementing the spec. It is (auto)configured with {@link SpringAddonsOidcClientProperties}.
 * </p>
 * <p>
 * <b>This implementation is not multi-tenant ready</b>. It will terminate the user session on this
 * application as well as on a single authorization-server (the one which emitted the access-token
 * with which the logout request is made).
 * </p>
 * <p>
 * This bean is auto-configured by {@link SpringAddonsOidcClientWithLoginBeans} as
 * {@link ConditionalOnMissingBean &#64;ConditionalOnMissingBean} of type
 * {@link LogoutSuccessHandler}. Usage:
 * </p>
 *
 * <pre>
 * SecurityFilterChain uiFilterChain(HttpSecurity http, LogoutSuccessHandler logoutSuccessHandler) {
 *   http.logout().logoutSuccessHandler(logoutSuccessHandler);
 * }
 * </pre>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see SpringAddonsOAuth2LogoutRequestUriBuilder
 * @see SpringAddonsOidcClientProperties
 */
@EqualsAndHashCode(callSuper = true)
public class SpringAddonsLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {
  private final LogoutRequestUriBuilder uriBuilder;
  private final ClientRegistrationRepository clientRegistrationRepository;
  private final SpringAddonsOauth2RedirectStrategy redirectStrategy;
  private final String defaultPostLogoutUri;
  private final List<Pattern> postLogoutAllowedUriPatterns;

  public SpringAddonsLogoutSuccessHandler(LogoutRequestUriBuilder uriBuilder,
      ClientRegistrationRepository clientRegistrationRepository,
      SpringAddonsOidcProperties addonsProperties) {
    this.postLogoutAllowedUriPatterns =
        addonsProperties.getClient().getPostLogoutAllowedUriPatterns();
    this.defaultPostLogoutUri =
        Optional.ofNullable(addonsProperties.getClient().getPostLogoutRedirectUri())
            .map(URI::toString).orElse(null);
    if (postLogoutAllowedUriPatterns.stream()
        .noneMatch(p -> p.matcher(defaultPostLogoutUri).matches())) {
      throw new MisconfiguredPostLogoutUriException(URI.create(defaultPostLogoutUri),
          postLogoutAllowedUriPatterns);
    }
    this.uriBuilder = uriBuilder;
    this.clientRegistrationRepository = clientRegistrationRepository;
    this.redirectStrategy = new SpringAddonsOauth2RedirectStrategy(
        addonsProperties.getClient().getOauth2Redirections().getRpInitiatedLogout());
  }

  @Override
  protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) {
    if (authentication instanceof OAuth2AuthenticationToken oauth
        && oauth.getPrincipal() instanceof OidcUser oidcUser) {
      final var postLogoutUri = Optional
          .ofNullable(
              request.getHeader(SpringAddonsOidcClientProperties.POST_LOGOUT_SUCCESS_URI_HEADER))
          .orElse(Optional
              .ofNullable(request
                  .getParameter(SpringAddonsOidcClientProperties.POST_LOGOUT_SUCCESS_URI_PARAM))
              .orElse(defaultPostLogoutUri));
      if (postLogoutAllowedUriPatterns.stream()
          .noneMatch(p -> p.matcher(postLogoutUri).matches())) {
        throw new InvalidRedirectionUriException(URI.create(postLogoutUri));
      }

      final var clientRegistration = clientRegistrationRepository
          .findByRegistrationId(oauth.getAuthorizedClientRegistrationId());
      final var uri = StringUtils.hasText(postLogoutUri)
          ? uriBuilder.getLogoutRequestUri(clientRegistration,
              oidcUser.getIdToken().getTokenValue(), Optional.of(URI.create(postLogoutUri)))
          : uriBuilder.getLogoutRequestUri(clientRegistration,
              oidcUser.getIdToken().getTokenValue());
      return uri.orElse(null);
    }
    return null;
  }

  @Override
  public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {
    this.redirectStrategy.sendRedirect(request, response,
        determineTargetUrl(request, response, authentication));
  }
}
