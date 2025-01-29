package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.StreamSupport;
import org.springframework.security.oauth2.client.AuthorizationCodeReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ClientCredentialsReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.DelegatingReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.JwtBearerReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.RefreshTokenReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.TokenExchangeReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveJwtBearerTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveTokenExchangeTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.web.reactive.function.client.WebClient;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import reactor.core.publisher.Mono;

/**
 * <p>
 * An alternative {@link ReactiveOAuth2AuthorizedClientProvider} to
 * {@link DelegatingReactiveOAuth2AuthorizedClientProvider} keeping a different provider for each
 * client registration. This allows to define for each a set of extra parameters to add to token
 * requests.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public final class PerRegistrationReactiveOAuth2AuthorizedClientProvider
    implements ReactiveOAuth2AuthorizedClientProvider {

  private final Map<String, DelegatingReactiveOAuth2AuthorizedClientProvider> providersByRegistrationId =
      new ConcurrentHashMap<>();
  private final Map<String, List<ReactiveOAuth2AuthorizedClientProvider>> customProvidersByRegistrationId;
  private final SpringAddonsOidcProperties addonsProperties;
  private final Map<String, WebClient> customTokenRestClientsByRegistrationId;

  public PerRegistrationReactiveOAuth2AuthorizedClientProvider(
      InMemoryReactiveClientRegistrationRepository clientRegistrationRepo,
      SpringAddonsOidcProperties addonsProperties,
      Map<String, WebClient> customTokenRestClientsByRegistrationId,
      Map<String, List<ReactiveOAuth2AuthorizedClientProvider>> customProvidersByRegistrationId) {
    this.customTokenRestClientsByRegistrationId = customTokenRestClientsByRegistrationId;
    this.customProvidersByRegistrationId = new HashMap<>(customProvidersByRegistrationId);
    this.addonsProperties = addonsProperties;

    StreamSupport.stream(clientRegistrationRepo.spliterator(), false).forEach(reg -> {
      final var delegate = new DelegatingReactiveOAuth2AuthorizedClientProvider(
          getProvidersFor(reg, addonsProperties));
      this.providersByRegistrationId.put(reg.getRegistrationId(), delegate);
    });
  }

  public PerRegistrationReactiveOAuth2AuthorizedClientProvider(
      InMemoryReactiveClientRegistrationRepository clientRegistrationRepo,
      SpringAddonsOidcProperties addonsProperties,
      Map<String, WebClient> customTokenRestClientsByRegistrationId) {
    this(clientRegistrationRepo, addonsProperties, customTokenRestClientsByRegistrationId,
        Map.of());
  }

  public PerRegistrationReactiveOAuth2AuthorizedClientProvider(
      InMemoryReactiveClientRegistrationRepository clientRegistrationRepo,
      SpringAddonsOidcProperties addonsProperties) {
    this(clientRegistrationRepo, addonsProperties, Map.of(), Map.of());
  }

  @Override
  public Mono<OAuth2AuthorizedClient> authorize(OAuth2AuthorizationContext context) {
    if (context == null) {
      return null;
    }
    final var registration = context.getClientRegistration();
    if (!providersByRegistrationId.containsKey(registration.getRegistrationId())) {
      final var delegate = new DelegatingReactiveOAuth2AuthorizedClientProvider(
          getProvidersFor(registration, addonsProperties));
      providersByRegistrationId.put(registration.getRegistrationId(), delegate);
    }

    return providersByRegistrationId.get(registration.getRegistrationId()).authorize(context);
  }

  private List<ReactiveOAuth2AuthorizedClientProvider> getProvidersFor(
      ClientRegistration registration, SpringAddonsOidcProperties addonsProperties) {
    if (AuthorizationGrantType.AUTHORIZATION_CODE
        .equals(registration.getAuthorizationGrantType())) {
      customProvidersByRegistrationId.computeIfAbsent(registration.getRegistrationId(),
          registrationId -> List.of(new AuthorizationCodeReactiveOAuth2AuthorizedClientProvider(),
              createRefreshTokenProvider(registration, addonsProperties)));
    } else if (AuthorizationGrantType.CLIENT_CREDENTIALS
        .equals(registration.getAuthorizationGrantType())) {
      customProvidersByRegistrationId.computeIfAbsent(registration.getRegistrationId(),
          registrationId -> List
              .of(createClientCredentialsProvider(registration, addonsProperties)));
    } else if (AuthorizationGrantType.TOKEN_EXCHANGE
        .equals(registration.getAuthorizationGrantType())) {
      customProvidersByRegistrationId.computeIfAbsent(registration.getRegistrationId(),
          registrationId -> List.of(createTokenExchangeProvider(registration, addonsProperties)));
    } else if (AuthorizationGrantType.JWT_BEARER.equals(registration.getAuthorizationGrantType())) {
      customProvidersByRegistrationId.computeIfAbsent(registration.getRegistrationId(),
          registrationId -> List.of(createJwtBearerProvider(registration, addonsProperties)));
    }
    return List.of();
  }

  private ClientCredentialsReactiveOAuth2AuthorizedClientProvider createClientCredentialsProvider(
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
    return provider;
  }

  private RefreshTokenReactiveOAuth2AuthorizedClientProvider createRefreshTokenProvider(
      ClientRegistration registration, SpringAddonsOidcProperties addonsProperties) {
    final var provider = new RefreshTokenReactiveOAuth2AuthorizedClientProvider();
    final var responseClient = new WebClientReactiveRefreshTokenTokenResponseClient();

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
