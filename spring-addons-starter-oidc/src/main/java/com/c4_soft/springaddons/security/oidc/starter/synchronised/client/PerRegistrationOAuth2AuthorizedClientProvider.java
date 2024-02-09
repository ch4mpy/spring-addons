package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.StreamSupport;

import org.springframework.security.oauth2.client.AuthorizationCodeOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ClientCredentialsOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.DelegatingOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.RefreshTokenOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.endpoint.DefaultClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.DefaultRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;

/**
 * <p>
 * An alternative {@link OAuth2AuthorizedClientProvider} to {@link DelegatingOAuth2AuthorizedClientProvider} keeping a different provider
 * for each client registration. This allows to define for each a set of extra parameters to add to token requests.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public final class PerRegistrationOAuth2AuthorizedClientProvider implements OAuth2AuthorizedClientProvider {

	private final Map<String, OAuth2AuthorizedClientProvider> providersByRegistrationId = new ConcurrentHashMap<>();
	private final Map<String, List<OAuth2AuthorizedClientProvider>> customProvidersByRegistrationId;
	private final SpringAddonsOidcProperties addonsProperties;

	public PerRegistrationOAuth2AuthorizedClientProvider(
			InMemoryClientRegistrationRepository clientRegistrationRepo,
			SpringAddonsOidcProperties addonsProperties,
			Map<String, List<OAuth2AuthorizedClientProvider>> customProvidersByRegistrationId) {
		this.customProvidersByRegistrationId = customProvidersByRegistrationId;
		this.addonsProperties = addonsProperties;
		StreamSupport.stream(clientRegistrationRepo.spliterator(), false).forEach(reg -> {
			final var delegate = new DelegatingOAuth2AuthorizedClientProvider(getProvidersFor(reg, addonsProperties));
			this.providersByRegistrationId.put(reg.getRegistrationId(), delegate);
		});
	}

	@Override
	public OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context) {
		if (context == null) {
			return null;
		}
		final var registration = context.getClientRegistration();
		if (!providersByRegistrationId.containsKey(registration.getRegistrationId())) {
			final var delegate = new DelegatingOAuth2AuthorizedClientProvider(getProvidersFor(registration, addonsProperties));
			providersByRegistrationId.put(registration.getRegistrationId(), delegate);
		}

		return providersByRegistrationId.get(registration.getRegistrationId()).authorize(context);
	}

	private List<OAuth2AuthorizedClientProvider> getProvidersFor(ClientRegistration registration, SpringAddonsOidcProperties addonsProperties) {
		final var providers = new ArrayList<>(customProvidersByRegistrationId.getOrDefault(registration.getRegistrationId(), List.of()));
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(registration.getAuthorizationGrantType())) {
			providers.add(new AuthorizationCodeOAuth2AuthorizedClientProvider());
			if (registration.getScopes().contains("offline_access")) {
				providers.add(createRefreshTokenProvider(registration, addonsProperties));
			}
		} else if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(registration.getAuthorizationGrantType())) {
			providers.add(createClientCredentialsProvider(registration, addonsProperties));
		}
		return providers;
	}

	private
			ClientCredentialsOAuth2AuthorizedClientProvider
			createClientCredentialsProvider(ClientRegistration registration, SpringAddonsOidcProperties addonsProperties) {
		final var provider = new ClientCredentialsOAuth2AuthorizedClientProvider();
		final var extraParameters = getExtraParameters(registration, addonsProperties);
		if (extraParameters.size() == 0) {
			return provider;
		}
		final var requestEntityConverter = new OAuth2ClientCredentialsGrantRequestEntityConverter();
		requestEntityConverter.addParametersConverter(source -> extraParameters);

		final var responseClient = new DefaultClientCredentialsTokenResponseClient();
		responseClient.setRequestEntityConverter(requestEntityConverter);

		provider.setAccessTokenResponseClient(responseClient);
		return provider;
	}

	private
			RefreshTokenOAuth2AuthorizedClientProvider
			createRefreshTokenProvider(ClientRegistration registration, SpringAddonsOidcProperties addonsProperties) {
		final var provider = new RefreshTokenOAuth2AuthorizedClientProvider();
		final var extraParameters = getExtraParameters(registration, addonsProperties);
		if (extraParameters.size() == 0) {
			return provider;
		}
		final var requestEntityConverter = new OAuth2RefreshTokenGrantRequestEntityConverter();
		requestEntityConverter.addParametersConverter(source -> extraParameters);

		final var responseClient = new DefaultRefreshTokenTokenResponseClient();
		responseClient.setRequestEntityConverter(requestEntityConverter);

		provider.setAccessTokenResponseClient(responseClient);
		return provider;
	}

	@SuppressWarnings("null")
	private MultiValueMap<String, String> getExtraParameters(ClientRegistration registration, SpringAddonsOidcProperties addonsProperties) {
		final var tokenParams = addonsProperties.getClient().getTokenRequestParams().getOrDefault(registration.getRegistrationId(), List.of());
		final MultiValueMap<String, String> extraParameters = new LinkedMultiValueMap<>(tokenParams.size());
		for (final var param : tokenParams) {
			if (param.getName() != null) {
				extraParameters.add(param.getName(), param.getValue());
			}
		}
		return extraParameters;
	}
}
