package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.time.Duration;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ClientCredentialsOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import com.c4_soft.springaddons.security.oidc.starter.TokenFlowRegistry;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties.SingleClientCredentialsFlowProperties;

/**
 * <p>
 * An {@link OAuth2AuthorizedClientProvider} decorating a
 * {@link ClientCredentialsOAuth2AuthorizedClientProvider} so that concurrent requests which would
 * send the very same token request share a single {@code client_credentials} flow, instead of each
 * firing its own.
 * </p>
 * <p>
 * An {@link AuthorizedClientServiceOAuth2AuthorizedClientManager} loads the authorized client from
 * its service, asks the provider to authorize it, and saves the result. These operations are not
 * atomic: all the requests observing the same expired (or missing) token send their own token
 * request, which makes as many calls to the token endpoint as there are concurrent requests (a
 * batch running hundreds of jobs in parallel, for instance). Spring Security leaves the
 * synchronization to the application, see <a href=
 * "https://github.com/spring-projects/spring-security/issues/11461">spring-security#11461</a>.
 * </p>
 * <p>
 * Here, the first request to reach the provider runs the flow and the others wait for its result:
 * the authorization server sees a single token request. Requests for other registrations or other
 * principals keep running in parallel, and requests holding a valid token are not delayed by more
 * than the delegate's expiry check. The result of a flow is also shared for a short while after it
 * completed, which covers the requests which had loaded the expired authorized client just before
 * the new one was saved.
 * </p>
 * <p>
 * This provider de-duplicates flows within a single JVM. In a horizontally scaled application, each
 * instance gets its own token.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see TokenFlowRegistry
 */
public final class SingleClientCredentialsFlowOAuth2AuthorizedClientProvider
    extends AbstractSingleTokenFlowOAuth2AuthorizedClientProvider {

  /**
   * @param delegate the provider actually running the {@code client_credentials} flow, usually a
   *        {@link ClientCredentialsOAuth2AuthorizedClientProvider}
   * @param timeout how long a request waits for the flow it joined before giving up
   * @param successCachingDuration how long the result of a successful flow is shared with new
   *        requests still holding the authorized client it was run for (or none)
   * @param errorCachingDuration how long the failure of a flow is shared with new requests still
   *        holding the authorized client it was run for (or none)
   */
  public SingleClientCredentialsFlowOAuth2AuthorizedClientProvider(
      OAuth2AuthorizedClientProvider delegate, Duration timeout, Duration successCachingDuration,
      Duration errorCachingDuration) {
    super(delegate, timeout, successCachingDuration, errorCachingDuration);
  }

  public SingleClientCredentialsFlowOAuth2AuthorizedClientProvider(
      OAuth2AuthorizedClientProvider delegate, SingleClientCredentialsFlowProperties properties) {
    this(delegate, properties.getTimeout(), properties.getSuccessCachingDuration(),
        properties.getErrorCachingDuration());
  }

  @Override
  protected boolean isApplicable(OAuth2AuthorizationContext context) {
    return AuthorizationGrantType.CLIENT_CREDENTIALS
        .equals(context.getClientRegistration().getAuthorizationGrantType());
  }

  @Override
  protected String flowName() {
    return AuthorizationGrantType.CLIENT_CREDENTIALS.getValue();
  }
}
