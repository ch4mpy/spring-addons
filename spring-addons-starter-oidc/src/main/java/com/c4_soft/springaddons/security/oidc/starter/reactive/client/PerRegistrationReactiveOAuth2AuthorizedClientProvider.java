package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;

import reactor.core.publisher.Mono;

/**
 * <p>
 * An alternative {@link ReactiveOAuth2AuthorizedClientProvider} to {@link DelegatingReactiveOAuth2AuthorizedClientProvider} keeping a different provider for
 * each client registration. This allows to define for each a set of extra parameters to add to token requests.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public final class PerRegistrationReactiveOAuth2AuthorizedClientProvider implements ReactiveOAuth2AuthorizedClientProvider {

    private final Map<String, ReactiveOAuth2AuthorizedClientProvider> providers;

    public PerRegistrationReactiveOAuth2AuthorizedClientProvider(
            SpringAddonsOidcProperties addonsProperties,
            Map<String, ReactiveOAuth2AuthorizedClientProvider> providers) {
        this.providers = new HashMap<>(providers);
    }

    public PerRegistrationReactiveOAuth2AuthorizedClientProvider(
            InMemoryReactiveClientRegistrationRepository clientRegistrationRepo,
            SpringAddonsOidcProperties addonsProperties,
            Map<String, ReactiveOAuth2AuthorizedClientProvider> customProviders) {
        this.providers = new HashMap<>(customProviders);
        StreamSupport.stream(clientRegistrationRepo.spliterator(), false).forEach(reg -> {
            if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(reg.getAuthorizationGrantType())) {
                this.providers.putIfAbsent(reg.getRegistrationId(), new AuthorizationCodeReactiveOAuth2AuthorizedClientProvider());
            } else if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(reg.getAuthorizationGrantType())) {
                this.providers.putIfAbsent(reg.getRegistrationId(), new ClientCredentialsReactiveOAuth2AuthorizedClientProvider());
            } else if (AuthorizationGrantType.REFRESH_TOKEN.equals(reg.getAuthorizationGrantType())) {
                this.providers.putIfAbsent(reg.getRegistrationId(), new RefreshTokenReactiveOAuth2AuthorizedClientProvider());
            } else {
                throw new UnsupportedGrantTypeException(reg.getAuthorizationGrantType());
            }

            final var tokenParams = addonsProperties.getClient().getTokenRequestParams().getOrDefault(reg.getRegistrationId(), List.of());
            if (tokenParams.isEmpty()) {
                return;
            }
            final MultiValueMap<String, String> extraParameters = new LinkedMultiValueMap<>(tokenParams.size());
            for (final var param : tokenParams) {
                extraParameters.add(param.getName(), param.getValue());
            }

            final var delegate = this.providers.get(reg.getRegistrationId());
            if (delegate instanceof ClientCredentialsReactiveOAuth2AuthorizedClientProvider clientCredentialsProvider) {
                final var clientCredentialsResponseClient = new WebClientReactiveClientCredentialsTokenResponseClient();
                clientCredentialsResponseClient.addParametersConverter(source -> extraParameters);

                clientCredentialsProvider.setAccessTokenResponseClient(clientCredentialsResponseClient);

            } else if (delegate instanceof RefreshTokenReactiveOAuth2AuthorizedClientProvider refreshTokenProvider) {
                final var refreshTokenResponseClient = new WebClientReactiveRefreshTokenTokenResponseClient();
                refreshTokenResponseClient.addParametersConverter(source -> extraParameters);

                refreshTokenProvider.setAccessTokenResponseClient(refreshTokenResponseClient);
            }
        });
    }

    public PerRegistrationReactiveOAuth2AuthorizedClientProvider(
            InMemoryReactiveClientRegistrationRepository clientRegistrationRepo,
            SpringAddonsOidcProperties addonsProperties) {
        this(clientRegistrationRepo, addonsProperties, Map.of());
    }

    @Override
    public Mono<OAuth2AuthorizedClient> authorize(OAuth2AuthorizationContext context) throws UnsupportedGrantTypeException {
        if (context == null) {
            return null;
        }

        final var provider = getDelegate(context.getClientRegistration().getRegistrationId());

        return provider.authorize(context);
    }

    @SuppressWarnings("unchecked")
    public <T extends ReactiveOAuth2AuthorizedClientProvider> T getDelegate(String registrationId) throws UnsupportedGrantTypeException {
        final var provider = providers.get(registrationId);
        return (T) provider;
    }

    public PerRegistrationReactiveOAuth2AuthorizedClientProvider setDelegate(String registrationId, ReactiveOAuth2AuthorizedClientProvider delegate) {
        Assert.notNull(registrationId, "registrationId cannot be null");
        Assert.notNull(delegate, "delegate cannot be null");
        providers.put(registrationId, delegate);
        return this;
    }

    static class UnsupportedGrantTypeException extends RuntimeException {
        private static final long serialVersionUID = 5600617070203595919L;

        public UnsupportedGrantTypeException(AuthorizationGrantType grantType) {
            super(
                "No OAuth2AuthorizedClientProvider registered for GrantType: %s. Consider adding one to SpringAddonsDelegatingOAuth2AuthorizedClientProvider in your conf."
                    .formatted(grantType));
        }
    }
}
