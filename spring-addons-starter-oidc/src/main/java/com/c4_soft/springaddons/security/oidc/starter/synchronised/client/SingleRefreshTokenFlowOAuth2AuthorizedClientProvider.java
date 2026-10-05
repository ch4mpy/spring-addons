package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.time.Duration;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.RefreshTokenOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import com.c4_soft.springaddons.security.oidc.starter.TokenFlowRegistry;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties.SingleRefreshTokenFlowProperties;

/**
 * <p>
 * An {@link OAuth2AuthorizedClientProvider} decorating a
 * {@link RefreshTokenOAuth2AuthorizedClientProvider} so that concurrent requests which would send
 * the very same token request share a single {@code refresh_token} flow, instead of each firing its
 * own.
 * </p>
 * <p>
 * Most authorization servers rotate refresh tokens: the one which was used is revoked as soon as a
 * new one is issued. When a user-agent sends parallel requests while the access token in session is
 * expired, Spring Security fires one {@code refresh_token} flow per request, only one of them can
 * succeed, and all the other requests are answered with a {@code 401}. Two requests sent in less
 * time than a token request takes are enough for this to happen. See <a href=
 * "https://github.com/spring-projects/spring-security/issues/15145">spring-security#15145</a>.
 * </p>
 * <p>
 * Here, the first request to reach the provider runs the flow and the others wait for its result:
 * the authorization server sees a single token request and the refresh token is spent exactly once.
 * Requests from other sessions hold other refresh tokens, so their flows keep running in parallel.
 * The result of a flow is also shared for a short while after it completed, which covers the
 * requests which had loaded the authorized client from the session just before the refreshed one
 * was saved there.
 * </p>
 * <p>
 * This provider de-duplicates flows within a single JVM. In a horizontally scaled application, use
 * sticky sessions (or accept one flow per instance).
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see TokenFlowRegistry
 */
public final class SingleRefreshTokenFlowOAuth2AuthorizedClientProvider
    extends AbstractSingleTokenFlowOAuth2AuthorizedClientProvider {

  /**
   * @param delegate the provider actually running the {@code refresh_token} flow, usually a
   *        {@link RefreshTokenOAuth2AuthorizedClientProvider}
   * @param timeout how long a request waits for the flow it joined before giving up
   * @param successCachingDuration how long the result of a successful flow is shared with new
   *        requests still holding the authorized client it was run for
   * @param errorCachingDuration how long the failure of a flow is shared with new requests still
   *        holding the authorized client it was run for
   */
  public SingleRefreshTokenFlowOAuth2AuthorizedClientProvider(
      OAuth2AuthorizedClientProvider delegate, Duration timeout, Duration successCachingDuration,
      Duration errorCachingDuration) {
    super(delegate, timeout, successCachingDuration, errorCachingDuration);
  }

  public SingleRefreshTokenFlowOAuth2AuthorizedClientProvider(
      OAuth2AuthorizedClientProvider delegate, SingleRefreshTokenFlowProperties properties) {
    this(delegate, properties.getTimeout(), properties.getSuccessCachingDuration(),
        properties.getErrorCachingDuration());
  }

  @Override
  protected boolean isApplicable(OAuth2AuthorizationContext context) {
    final var authorizedClient = context.getAuthorizedClient();
    return authorizedClient != null && authorizedClient.getRefreshToken() != null;
  }

  @Override
  protected String flowName() {
    return AuthorizationGrantType.REFRESH_TOKEN.getValue();
  }
}
