package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.StreamSupport;

import org.springframework.security.oauth2.client.AuthorizationCodeReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ClientCredentialsReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.DelegatingReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.RefreshTokenReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;

import reactor.core.publisher.Mono;

/**
 * <p>
 * An alternative {@link ReactiveOAuth2AuthorizedClientProvider} to {@link DelegatingReactiveOAuth2AuthorizedClientProvider} keeping a
 * different provider for each client registration. This allows to define for each a set of extra parameters to add to token requests.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public final class PerRegistrationReactiveOAuth2AuthorizedClientProvider implements ReactiveOAuth2AuthorizedClientProvider {

	private final Map<String, DelegatingReactiveOAuth2AuthorizedClientProvider> providersByRegistrationId = new ConcurrentHashMap<>();
	private final Map<String, List<ReactiveOAuth2AuthorizedClientProvider>> customProvidersByRegistrationId;
	private final SpringAddonsOidcProperties addonsProperties;

	public PerRegistrationReactiveOAuth2AuthorizedClientProvider(
			InMemoryReactiveClientRegistrationRepository clientRegistrationRepo,
			SpringAddonsOidcProperties addonsProperties,
			Map<String, List<ReactiveOAuth2AuthorizedClientProvider>> customProvidersByRegistrationId) {
		this.customProvidersByRegistrationId = customProvidersByRegistrationId;
		this.addonsProperties = addonsProperties;

		StreamSupport.stream(clientRegistrationRepo.spliterator(), false).forEach(reg -> {
			final var delegate = new DelegatingReactiveOAuth2AuthorizedClientProvider(getProvidersFor(reg, addonsProperties));
			this.providersByRegistrationId.put(reg.getRegistrationId(), delegate);
		});
	}

	@Override
	public Mono<OAuth2AuthorizedClient> authorize(OAuth2AuthorizationContext context) {
		if (context == null) {
			return null;
		}
		final var registration = context.getClientRegistration();
		if (!providersByRegistrationId.containsKey(registration.getRegistrationId())) {
			final var delegate = new DelegatingReactiveOAuth2AuthorizedClientProvider(getProvidersFor(registration, addonsProperties));
			providersByRegistrationId.put(registration.getRegistrationId(), delegate);
		}

		return providersByRegistrationId.get(registration.getRegistrationId()).authorize(context);
	}

	private List<ReactiveOAuth2AuthorizedClientProvider> getProvidersFor(ClientRegistration registration, SpringAddonsOidcProperties addonsProperties) {
		final var providers = new ArrayList<>(customProvidersByRegistrationId.getOrDefault(registration.getRegistrationId(), List.of()));
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(registration.getAuthorizationGrantType())) {
			providers.add(new AuthorizationCodeReactiveOAuth2AuthorizedClientProvider());
			if (registration.getScopes().contains("offline_access")) {
				providers.add(createRefreshTokenProvider(registration, addonsProperties));
			}
		} else if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(registration.getAuthorizationGrantType())) {
			providers.add(createClientCredentialsProvider(registration, addonsProperties));
		}
		return providers;
	}

	private
			ClientCredentialsReactiveOAuth2AuthorizedClientProvider
			createClientCredentialsProvider(ClientRegistration registration, SpringAddonsOidcProperties addonsProperties) {
		final var provider = new ClientCredentialsReactiveOAuth2AuthorizedClientProvider();
		final var extraParameters = addonsProperties.getClient().getExtraTokenParameters(registration.getRegistrationId());
		if (extraParameters.size() == 0) {
			return provider;
		}

		final var responseClient = new WebClientReactiveClientCredentialsTokenResponseClient();
		responseClient.addParametersConverter(source -> extraParameters);

		provider.setAccessTokenResponseClient(responseClient);
		return provider;
	}

	private
			RefreshTokenReactiveOAuth2AuthorizedClientProvider
			createRefreshTokenProvider(ClientRegistration registration, SpringAddonsOidcProperties addonsProperties) {
		final var provider = new RefreshTokenReactiveOAuth2AuthorizedClientProvider();
		final var extraParameters = addonsProperties.getClient().getExtraTokenParameters(registration.getRegistrationId());
		if (extraParameters.size() == 0) {
			return provider;
		}

		final var responseClient = new WebClientReactiveRefreshTokenTokenResponseClient();
		responseClient.addParametersConverter(source -> extraParameters);

		provider.setAccessTokenResponseClient(responseClient);
		return provider;
	}
}
