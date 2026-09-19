package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import com.c4_soft.springaddons.security.oidc.starter.LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oidc.starter.SpringAddonsOAuth2LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oidc.starter.properties.InvalidRedirectionUriException;
import com.c4_soft.springaddons.security.oidc.starter.properties.MisconfiguredPostLogoutUriException;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import reactor.core.publisher.Mono;

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
 * This bean is auto-configured by {@link ReactiveSpringAddonsOidcClientWithLoginBeans} as
 * {@link ConditionalOnMissingBean &#64;ConditionalOnMissingBean} of type
 * {@link ServerLogoutSuccessHandler}. Usage:
 * </p>
 *
 * <pre>
 * SecurityFilterChain uiFilterChain(HttpSecurity http,
 *     ServerLogoutSuccessHandler logoutSuccessHandler) {
 *   http.logout().logoutSuccessHandler(logoutSuccessHandler);
 * }
 * </pre>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see SpringAddonsOAuth2LogoutRequestUriBuilder
 * @see SpringAddonsOidcClientProperties
 */
public class SpringAddonsServerLogoutSuccessHandler implements ServerLogoutSuccessHandler {

  private final LogoutRequestUriBuilder uriBuilder;
  private final ReactiveClientRegistrationRepository clientRegistrationRepo;
  private final ServerRedirectStrategy redirectStrategy;
  private final String defaultPostLogoutUri;
  private final List<Pattern> postLogoutAllowedUriPatterns;

  public SpringAddonsServerLogoutSuccessHandler(LogoutRequestUriBuilder uriBuilder,
      ReactiveClientRegistrationRepository clientRegistrationRepo,
      SpringAddonsOidcProperties addonsProperties) {
    this.postLogoutAllowedUriPatterns =
        addonsProperties.getClient().getPostLogoutAllowedUriPatterns();
    this.defaultPostLogoutUri =
        Optional.ofNullable(addonsProperties.getClient().getPostLogoutRedirectUri())
            .map(URI::toString).orElse(null);
    if (!SpringAddonsOidcClientProperties.isAllowedRedirectionUri(defaultPostLogoutUri,
        postLogoutAllowedUriPatterns)) {
      throw new MisconfiguredPostLogoutUriException(URI.create(defaultPostLogoutUri),
          postLogoutAllowedUriPatterns);
    }
    this.uriBuilder = uriBuilder;
    this.clientRegistrationRepo = clientRegistrationRepo;
    this.redirectStrategy = new SpringAddonsOauth2ServerRedirectStrategy(
        addonsProperties.getClient().getOauth2Redirections().getRpInitiatedLogout());
  }

  /**
   * Redirects to the RP-Initiated Logout request URI for OIDC users, and to the post-logout URI for
   * other users (OAuth2 login without OpenID, or no authentication at all)
   */
  @Override
  public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
    return Mono.defer(() -> {
      final var postLogoutUri = Optional
          .ofNullable(exchange.getExchange().getRequest().getHeaders()
              .getFirst(SpringAddonsOidcClientProperties.POST_LOGOUT_SUCCESS_URI_HEADER))
          .orElse(Optional
              .ofNullable(exchange.getExchange().getRequest().getQueryParams()
                  .getFirst(SpringAddonsOidcClientProperties.POST_LOGOUT_SUCCESS_URI_PARAM))
              .orElse(defaultPostLogoutUri));
      if (!SpringAddonsOidcClientProperties.isAllowedRedirectionUri(postLogoutUri,
          postLogoutAllowedUriPatterns)) {
        return Mono.error(new InvalidRedirectionUriException(postLogoutUri));
      }

      final Mono<String> targetUri;
      if (authentication instanceof OAuth2AuthenticationToken oauth
          && oauth.getPrincipal() instanceof OidcUser oidcUser) {
        targetUri = clientRegistrationRepo
            .findByRegistrationId(oauth.getAuthorizedClientRegistrationId())
            .flatMap(client -> Mono.justOrEmpty(uriBuilder.getLogoutRequestUri(client,
                oidcUser.getIdToken().getTokenValue(), Optional.of(URI.create(postLogoutUri)))))
            .defaultIfEmpty(postLogoutUri);
      } else {
        targetUri = Mono.just(postLogoutUri);
      }

      return targetUri.flatMap(
          uri -> this.redirectStrategy.sendRedirect(exchange.getExchange(), URI.create(uri)));
    });
  }
}
