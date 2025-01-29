package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.StreamSupport;
import org.springframework.security.oauth2.client.AuthorizationCodeOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ClientCredentialsOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.DelegatingOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.JwtBearerOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.RefreshTokenOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.TokenExchangeOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.endpoint.RestClientClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.RestClientJwtBearerTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.RestClientRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.RestClientTokenExchangeTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.web.client.RestClient;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;

/**
 * <p>
 * An alternative {@link OAuth2AuthorizedClientProvider} to
 * {@link DelegatingOAuth2AuthorizedClientProvider} keeping a different provider for each client
 * registration. This allows to define for each a set of extra parameters to add to token requests.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public final class PerRegistrationOAuth2AuthorizedClientProvider
    implements OAuth2AuthorizedClientProvider {

  private final Map<String, OAuth2AuthorizedClientProvider> providersByRegistrationId =
      new ConcurrentHashMap<>();
  private final Map<String, List<OAuth2AuthorizedClientProvider>> customProvidersByRegistrationId;
  private final SpringAddonsOidcProperties addonsProperties;
  private final Map<String, RestClient> customTokenRestClientsByRegistrationId;

  public PerRegistrationOAuth2AuthorizedClientProvider(
      InMemoryClientRegistrationRepository clientRegistrationRepo,
      SpringAddonsOidcProperties addonsProperties,
      Map<String, RestClient> customTokenRestClientsByRegistrationId,
      Map<String, List<OAuth2AuthorizedClientProvider>> customProvidersByRegistrationId) {
    this.customProvidersByRegistrationId = new HashMap<>(customProvidersByRegistrationId);
    this.addonsProperties = addonsProperties;
    this.customTokenRestClientsByRegistrationId = customTokenRestClientsByRegistrationId;
    StreamSupport.stream(clientRegistrationRepo.spliterator(), false).forEach(reg -> {
      final var delegate =
          new DelegatingOAuth2AuthorizedClientProvider(getProvidersFor(reg, addonsProperties));
      this.providersByRegistrationId.put(reg.getRegistrationId(), delegate);
    });
  }

  public PerRegistrationOAuth2AuthorizedClientProvider(
      InMemoryClientRegistrationRepository clientRegistrationRepo,
      SpringAddonsOidcProperties addonsProperties,
      Map<String, RestClient> customTokenRestClientsByRegistrationId) {
    this(clientRegistrationRepo, addonsProperties, customTokenRestClientsByRegistrationId,
        Map.of());
  }

  public PerRegistrationOAuth2AuthorizedClientProvider(
      InMemoryClientRegistrationRepository clientRegistrationRepo,
      SpringAddonsOidcProperties addonsProperties) {
    this(clientRegistrationRepo, addonsProperties, Map.of(), Map.of());
  }

  @Override
  public OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context) {
    if (context == null) {
      return null;
    }
    final var registration = context.getClientRegistration();
    if (!providersByRegistrationId.containsKey(registration.getRegistrationId())) {
      final var delegate = new DelegatingOAuth2AuthorizedClientProvider(
          getProvidersFor(registration, addonsProperties));
      providersByRegistrationId.put(registration.getRegistrationId(), delegate);
    }

    return providersByRegistrationId.get(registration.getRegistrationId()).authorize(context);
  }

  private List<OAuth2AuthorizedClientProvider> getProvidersFor(ClientRegistration registration,
      SpringAddonsOidcProperties addonsProperties) {
    if (AuthorizationGrantType.AUTHORIZATION_CODE
        .equals(registration.getAuthorizationGrantType())) {
      return customProvidersByRegistrationId.computeIfAbsent(registration.getRegistrationId(),
          registrationId -> List.of(new AuthorizationCodeOAuth2AuthorizedClientProvider(),
              createRefreshTokenProvider(registration, addonsProperties)));
    } else if (AuthorizationGrantType.CLIENT_CREDENTIALS
        .equals(registration.getAuthorizationGrantType())) {
      return customProvidersByRegistrationId.computeIfAbsent(registration.getRegistrationId(),
          registrationId -> List
              .of(createClientCredentialsProvider(registration, addonsProperties)));
    } else if (AuthorizationGrantType.TOKEN_EXCHANGE
        .equals(registration.getAuthorizationGrantType())) {
      return customProvidersByRegistrationId.computeIfAbsent(registration.getRegistrationId(),
          registrationId -> List.of(createTokenExchangeProvider(registration, addonsProperties)));
    } else if (AuthorizationGrantType.JWT_BEARER.equals(registration.getAuthorizationGrantType())) {
      return customProvidersByRegistrationId.computeIfAbsent(registration.getRegistrationId(),
          registrationId -> List.of(createJwtBearerProvider(registration, addonsProperties)));
    }
    return List.of();
  }

  private ClientCredentialsOAuth2AuthorizedClientProvider createClientCredentialsProvider(
      ClientRegistration registration, SpringAddonsOidcProperties addonsProperties) {
    final var responseClient = new RestClientClientCredentialsTokenResponseClient();
    final var provider = new ClientCredentialsOAuth2AuthorizedClientProvider();

    if (customTokenRestClientsByRegistrationId.containsKey(registration.getRegistrationId())) {
      responseClient.setRestClient(
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

  private RefreshTokenOAuth2AuthorizedClientProvider createRefreshTokenProvider(
      ClientRegistration registration, SpringAddonsOidcProperties addonsProperties) {
    final var responseClient = new RestClientRefreshTokenTokenResponseClient();
    final var provider = new RefreshTokenOAuth2AuthorizedClientProvider();

    if (customTokenRestClientsByRegistrationId.containsKey(registration.getRegistrationId())) {
      responseClient.setRestClient(
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

  private TokenExchangeOAuth2AuthorizedClientProvider createTokenExchangeProvider(
      ClientRegistration registration, SpringAddonsOidcProperties addonsProperties) {
    final var responseClient = new RestClientTokenExchangeTokenResponseClient();
    final var provider = new TokenExchangeOAuth2AuthorizedClientProvider();

    if (customTokenRestClientsByRegistrationId.containsKey(registration.getRegistrationId())) {
      responseClient.setRestClient(
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

  private JwtBearerOAuth2AuthorizedClientProvider createJwtBearerProvider(
      ClientRegistration registration, SpringAddonsOidcProperties addonsProperties) {
    final var responseClient = new RestClientJwtBearerTokenResponseClient();
    final var provider = new JwtBearerOAuth2AuthorizedClientProvider();

    if (customTokenRestClientsByRegistrationId.containsKey(registration.getRegistrationId())) {
      responseClient.setRestClient(
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
