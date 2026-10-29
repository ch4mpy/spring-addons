package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.AuthorizationCodeReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.ClientCredentialsReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.DelegatingReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.JwtBearerReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.RefreshTokenReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.TokenExchangeReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveJwtBearerTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveTokenExchangeTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.util.Assert;
import org.springframework.web.reactive.function.client.WebClient;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * <p>
 * An alternative {@link ReactiveOAuth2AuthorizedClientProvider} to
 * {@link DelegatingReactiveOAuth2AuthorizedClientProvider} keeping a different provider for each
 * client registration. This allows to define for each a set of extra parameters to add to token
 * requests.
 * </p>
 * <p>
 * After each refresh, the {@code refresh_token} providers it builds call the
 * {@link #setRefreshTokenSuccessHandler(ReactiveOAuth2AuthorizationSuccessHandler) refresh_token
 * success handler}, by default a {@link RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler}
 * with Spring Security's defaults: with {@code oauth2Login}, it validates the refreshed ID token and
 * replaces the {@code OidcUser} and authorities in the session. When it refuses the refreshed
 * identity with an {@link AuthenticationException}, it is rethrown as a
 * {@link ClientAuthorizationException} with the {@code invalid_grant} error, and without cause: the
 * authorized client is removed and the user must log in again, as when the authorization server
 * refuses the refresh.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Slf4j
public final class PerRegistrationReactiveOAuth2AuthorizedClientProvider
    implements ReactiveOAuth2AuthorizedClientProvider {

  private final Map<String, DelegatingReactiveOAuth2AuthorizedClientProvider> providersByRegistrationId =
      new ConcurrentHashMap<>();
  private final Map<String, List<ReactiveOAuth2AuthorizedClientProvider>> customProvidersByRegistrationId;
  private final SpringAddonsOidcProperties addonsProperties;
  private final Map<String, WebClient> customTokenRestClientsByRegistrationId;
  private volatile ReactiveOAuth2AuthorizationSuccessHandler refreshTokenSuccessHandler =
      new RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler();

  /**
   * @param clientRegistrationRepo providers are built eagerly for the registrations of repositories
   *        which are {@link Iterable} (like {@link InMemoryReactiveClientRegistrationRepository}),
   *        and lazily, at first {@link #authorize(OAuth2AuthorizationContext)}, for the others
   * @param addonsProperties spring-addons properties (extra token request parameters,
   *        single-refresh-token-flow and single-client-credentials-flow configuration are read from
   *        it)
   * @param customTokenRestClientsByRegistrationId {@link WebClient} to use for token requests, by
   *        registration ID (Spring Security default is used for registrations without an entry)
   * @param customProvidersByRegistrationId providers to use for registrations for which the
   *        default ones are not suitable
   */
  public PerRegistrationReactiveOAuth2AuthorizedClientProvider(
      ReactiveClientRegistrationRepository clientRegistrationRepo,
      SpringAddonsOidcProperties addonsProperties,
      Map<String, WebClient> customTokenRestClientsByRegistrationId,
      Map<String, List<ReactiveOAuth2AuthorizedClientProvider>> customProvidersByRegistrationId) {
    this.customTokenRestClientsByRegistrationId = customTokenRestClientsByRegistrationId;
    this.customProvidersByRegistrationId = new HashMap<>(customProvidersByRegistrationId);
    this.addonsProperties = addonsProperties;

    if (clientRegistrationRepo instanceof Iterable<?> registrations) {
      for (final var registration : registrations) {
        if (registration instanceof ClientRegistration reg) {
          this.providersByRegistrationId.put(reg.getRegistrationId(), createDelegate(reg));
        }
      }
    }
  }

  public PerRegistrationReactiveOAuth2AuthorizedClientProvider(
      ReactiveClientRegistrationRepository clientRegistrationRepo,
      SpringAddonsOidcProperties addonsProperties,
      Map<String, WebClient> customTokenRestClientsByRegistrationId) {
    this(clientRegistrationRepo, addonsProperties, customTokenRestClientsByRegistrationId,
        Map.of());
  }

  public PerRegistrationReactiveOAuth2AuthorizedClientProvider(
      ReactiveClientRegistrationRepository clientRegistrationRepo,
      SpringAddonsOidcProperties addonsProperties) {
    this(clientRegistrationRepo, addonsProperties, Map.of(), Map.of());
  }

  @Override
  public Mono<OAuth2AuthorizedClient> authorize(OAuth2AuthorizationContext context) {
    if (context == null) {
      return null;
    }
    final var registration = context.getClientRegistration();
    return providersByRegistrationId
        .computeIfAbsent(registration.getRegistrationId(),
            registrationId -> createDelegate(registration))
        .authorize(context);
  }

  /**
   * @param refreshTokenSuccessHandler called after each refresh by the {@code refresh_token}
   *        providers, usually a {@link RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler}
   *        configured with the authorities mapper, user service and ID token decoder factory of
   *        {@code oauth2Login}
   */
  public void setRefreshTokenSuccessHandler(
      ReactiveOAuth2AuthorizationSuccessHandler refreshTokenSuccessHandler) {
    Assert.notNull(refreshTokenSuccessHandler, "refreshTokenSuccessHandler cannot be null");
    this.refreshTokenSuccessHandler = refreshTokenSuccessHandler;
  }

  private DelegatingReactiveOAuth2AuthorizedClientProvider createDelegate(
      ClientRegistration registration) {
    return new DelegatingReactiveOAuth2AuthorizedClientProvider(
        getProvidersFor(registration, addonsProperties));
  }

  /**
   * @return the custom providers given for the registration, if any, or the default ones for its
   *         grant type
   */
  private List<ReactiveOAuth2AuthorizedClientProvider> getProvidersFor(
      ClientRegistration registration, SpringAddonsOidcProperties addonsProperties) {
    final var customProviders = customProvidersByRegistrationId.get(registration.getRegistrationId());
    if (customProviders != null) {
      return customProviders;
    }
    if (AuthorizationGrantType.AUTHORIZATION_CODE
        .equals(registration.getAuthorizationGrantType())) {
      return List.of(new AuthorizationCodeReactiveOAuth2AuthorizedClientProvider(),
          createRefreshTokenProvider(registration, addonsProperties));
    } else if (AuthorizationGrantType.CLIENT_CREDENTIALS
        .equals(registration.getAuthorizationGrantType())) {
      return List.of(createClientCredentialsProvider(registration, addonsProperties));
    } else if (AuthorizationGrantType.TOKEN_EXCHANGE
        .equals(registration.getAuthorizationGrantType())) {
      return List.of(createTokenExchangeProvider(registration, addonsProperties));
    } else if (AuthorizationGrantType.JWT_BEARER.equals(registration.getAuthorizationGrantType())) {
      return List.of(createJwtBearerProvider(registration, addonsProperties));
    }
    return List.of();
  }

  /**
   * @param registration the client registration to build a {@code client_credentials} provider for
   * @param addonsProperties spring-addons configuration properties
   * @return a {@link ClientCredentialsReactiveOAuth2AuthorizedClientProvider}, decorated with a
   *         {@link SingleClientCredentialsFlowReactiveOAuth2AuthorizedClientProvider} unless
   *         {@code com.c4-soft.springaddons.oidc.client.single-client-credentials-flow.enabled} is
   *         set to {@code false}
   */
  private ReactiveOAuth2AuthorizedClientProvider createClientCredentialsProvider(
      ClientRegistration registration, SpringAddonsOidcProperties addonsProperties) {
    final var provider = new ClientCredentialsReactiveOAuth2AuthorizedClientProvider();
    final var responseClient = new WebClientReactiveClientCredentialsTokenResponseClient();

    if (customTokenRestClientsByRegistrationId.containsKey(registration.getRegistrationId())) {
      responseClient.setWebClient(
          customTokenRestClientsByRegistrationId.get(registration.getRegistrationId()));
    }

    final var extraParameters =
        addonsProperties.getClient().getExtraTokenParameters(registration.getRegistrationId());
    if (extraParameters.size() > 0) {
      responseClient.setParametersCustomizer(parameters -> parameters.addAll(extraParameters));
    }

    provider.setAccessTokenResponseClient(responseClient);

    final var singleFlow = addonsProperties.getClient().getSingleClientCredentialsFlow();
    if (!singleFlow.isEnabled()) {
      return provider;
    }
    return new SingleClientCredentialsFlowReactiveOAuth2AuthorizedClientProvider(provider,
        singleFlow);
  }

  /**
   * @param registration the client registration to build a {@code refresh_token} provider for
   * @param addonsProperties spring-addons configuration properties
   * @return a {@link RefreshTokenReactiveOAuth2AuthorizedClientProvider}, decorated with a
   *         {@link SingleRefreshTokenFlowReactiveOAuth2AuthorizedClientProvider} unless
   *         {@code com.c4-soft.springaddons.oidc.client.single-refresh-token-flow.enabled} is set
   *         to {@code false}
   */
  private ReactiveOAuth2AuthorizedClientProvider createRefreshTokenProvider(
      ClientRegistration registration, SpringAddonsOidcProperties addonsProperties) {
    final var registrationId = registration.getRegistrationId();
    final var provider = new RefreshTokenReactiveOAuth2AuthorizedClientProvider();
    // Read when called: the providers of iterable repositories are built before the setter runs
    provider.setAuthorizationSuccessHandler((authorizedClient, principal,
        attributes) -> onRefreshTokenSuccess(authorizedClient, principal, attributes, registrationId));
    final var responseClient = new WebClientReactiveRefreshTokenTokenResponseClient();

    if (customTokenRestClientsByRegistrationId.containsKey(registrationId)) {
      responseClient.setWebClient(customTokenRestClientsByRegistrationId.get(registrationId));
    }

    final var extraParameters = addonsProperties.getClient().getExtraTokenParameters(registrationId);
    if (extraParameters.size() > 0) {
      responseClient.setParametersCustomizer(parameters -> parameters.addAll(extraParameters));
    }

    provider.setAccessTokenResponseClient(responseClient);

    final var singleFlow = addonsProperties.getClient().getSingleRefreshTokenFlow();
    if (!singleFlow.isEnabled()) {
      return provider;
    }
    return new SingleRefreshTokenFlowReactiveOAuth2AuthorizedClientProvider(provider, singleFlow);
  }

  /**
   * The original {@link AuthenticationException} is suppressed, not the cause, as in the servlet
   * {@code PerRegistrationOAuth2AuthorizedClientProvider}.
   */
  private Mono<Void> onRefreshTokenSuccess(OAuth2AuthorizedClient authorizedClient,
      Authentication principal, Map<String, Object> attributes, String registrationId) {
    return Mono
        .defer(() -> refreshTokenSuccessHandler.onAuthorizationSuccess(authorizedClient, principal,
            attributes))
        .onErrorMap(AuthenticationException.class, e -> {
          log.debug("The refreshed identity was refused for registration {}", registrationId, e);
          final var reason = e instanceof OAuth2AuthenticationException oauth2Exception
              ? oauth2Exception.getError().toString()
              : e.toString();
          final var translated = new ClientAuthorizationException(
              new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT,
                  "The refreshed identity was refused: " + reason, null),
              registrationId);
          translated.addSuppressed(e);
          return translated;
        });
  }

  private TokenExchangeReactiveOAuth2AuthorizedClientProvider createTokenExchangeProvider(
      ClientRegistration registration, SpringAddonsOidcProperties addonsProperties) {
    final var provider = new TokenExchangeReactiveOAuth2AuthorizedClientProvider();
    final var responseClient = new WebClientReactiveTokenExchangeTokenResponseClient();

    if (customTokenRestClientsByRegistrationId.containsKey(registration.getRegistrationId())) {
      responseClient.setWebClient(
          customTokenRestClientsByRegistrationId.get(registration.getRegistrationId()));
    }

    final var extraParameters =
        addonsProperties.getClient().getExtraTokenParameters(registration.getRegistrationId());
    if (extraParameters.size() > 0) {
      responseClient.setParametersCustomizer(parameters -> parameters.addAll(extraParameters));
    }

    provider.setAccessTokenResponseClient(responseClient);
    return provider;
  }

  private JwtBearerReactiveOAuth2AuthorizedClientProvider createJwtBearerProvider(
      ClientRegistration registration, SpringAddonsOidcProperties addonsProperties) {
    final var provider = new JwtBearerReactiveOAuth2AuthorizedClientProvider();
    final var responseClient = new WebClientReactiveJwtBearerTokenResponseClient();

    if (customTokenRestClientsByRegistrationId.containsKey(registration.getRegistrationId())) {
      responseClient.setWebClient(
          customTokenRestClientsByRegistrationId.get(registration.getRegistrationId()));
    }

    final var extraParameters =
        addonsProperties.getClient().getExtraTokenParameters(registration.getRegistrationId());
    if (extraParameters.size() > 0) {
      responseClient.setParametersCustomizer(parameters -> parameters.addAll(extraParameters));
    }

    provider.setAccessTokenResponseClient(responseClient);
    return provider;
  }
}
