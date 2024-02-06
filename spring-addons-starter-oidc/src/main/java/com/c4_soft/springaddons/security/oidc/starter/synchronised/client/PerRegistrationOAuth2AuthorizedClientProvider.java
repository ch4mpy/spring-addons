package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;

/**
 * <p>
 * An alternative {@link OAuth2AuthorizedClientProvider} to {@link DelegatingOAuth2AuthorizedClientProvider} keeping a different provider for each client
 * registration. This allows to define for each a set of extra parameters to add to token requests.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public final class PerRegistrationOAuth2AuthorizedClientProvider implements OAuth2AuthorizedClientProvider {

    private final Map<String, OAuth2AuthorizedClientProvider> providers;

    public PerRegistrationOAuth2AuthorizedClientProvider(SpringAddonsOidcProperties addonsProperties, Map<String, OAuth2AuthorizedClientProvider> providers) {
        this.providers = new HashMap<>(providers);
    }

    public PerRegistrationOAuth2AuthorizedClientProvider(
            InMemoryClientRegistrationRepository clientRegistrationRepo,
            SpringAddonsOidcProperties addonsProperties,
            Map<String, OAuth2AuthorizedClientProvider> customProviders) {
        this.providers = new HashMap<>(customProviders);
        StreamSupport.stream(clientRegistrationRepo.spliterator(), false).forEach(reg -> {
            if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(reg.getAuthorizationGrantType())) {
                this.providers.putIfAbsent(reg.getRegistrationId(), new AuthorizationCodeOAuth2AuthorizedClientProvider());
            } else if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(reg.getAuthorizationGrantType())) {
                this.providers.putIfAbsent(reg.getRegistrationId(), new ClientCredentialsOAuth2AuthorizedClientProvider());
            } else if (AuthorizationGrantType.REFRESH_TOKEN.equals(reg.getAuthorizationGrantType())) {
                this.providers.putIfAbsent(reg.getRegistrationId(), new RefreshTokenOAuth2AuthorizedClientProvider());
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
            if (delegate instanceof ClientCredentialsOAuth2AuthorizedClientProvider clientCredentialsProvider) {
                final var requestEntityConverter = new OAuth2ClientCredentialsGrantRequestEntityConverter();
                requestEntityConverter.addParametersConverter(source -> extraParameters);

                final var clientCredentialsResponseClient = new DefaultClientCredentialsTokenResponseClient();
                clientCredentialsResponseClient.setRequestEntityConverter(requestEntityConverter);

                clientCredentialsProvider.setAccessTokenResponseClient(clientCredentialsResponseClient);

            } else if (delegate instanceof RefreshTokenOAuth2AuthorizedClientProvider refreshTokenProvider) {
                final var requestEntityConverter = new OAuth2RefreshTokenGrantRequestEntityConverter();
                requestEntityConverter.addParametersConverter(source -> extraParameters);

                final var refreshTokenResponseClient = new DefaultRefreshTokenTokenResponseClient();
                refreshTokenResponseClient.setRequestEntityConverter(requestEntityConverter);

                refreshTokenProvider.setAccessTokenResponseClient(refreshTokenResponseClient);
            }
        });
    }

    public PerRegistrationOAuth2AuthorizedClientProvider(
            InMemoryClientRegistrationRepository clientRegistrationRepo,
            SpringAddonsOidcProperties addonsProperties) {
        this(clientRegistrationRepo, addonsProperties, Map.of());
    }

    @Override
    public OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context) throws UnsupportedGrantTypeException {
        if (context == null) {
            return null;
        }

        final var provider = getDelegate(context.getClientRegistration().getRegistrationId());

        return provider.authorize(context);
    }

    @SuppressWarnings("unchecked")
    public <T extends OAuth2AuthorizedClientProvider> T getDelegate(String registrationId) throws UnsupportedGrantTypeException {
        final var provider = providers.get(registrationId);
        return (T) provider;
    }

    public PerRegistrationOAuth2AuthorizedClientProvider setDelegate(String registrationId, OAuth2AuthorizedClientProvider delegate) {
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
