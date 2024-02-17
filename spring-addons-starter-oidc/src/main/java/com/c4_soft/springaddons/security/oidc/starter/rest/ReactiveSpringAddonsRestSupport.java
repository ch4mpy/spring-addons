package com.c4_soft.springaddons.security.oidc.starter.rest;

import java.util.List;
import java.util.Optional;

import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.support.WebClientAdapter;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties.RestProperties;

import lombok.Data;
import lombok.EqualsAndHashCode;
import reactor.core.publisher.Mono;

/**
 * <p>
 * Helps building {@link WebClient} instances. Main features are:
 * </p>
 * <ul>
 * <li>providing with builders pre-configured for OAuth2: add a Bearer Authorization header provided by the {@link ReactiveOAuth2AuthorizedClientManager} for a
 * given registration-id or by a {@link BearerProvider} (taking the Bearer from the security context to forward it)</li>
 * <li>providing with helper methods to get a HTTP service from the {@link HttpServiceProxyFactory} and application properties</li>
 * </ul>
 * <p>
 * <p>
 * When spring-addons {@link RestProperties#forwardBearer} is true, the Bearer is taken from the {@link BearerProvider} in the context,
 * {@link DefaultBearerProvider} by default which works only with {@link JwtAuthenticationToken} or {@link BearerTokenAuthentication}. You must provide with
 * your own {@link BearerProvider} bean if your security configuration populates the security context with something else.
 * </p>
 * <p>
 * <b>/!\ Auto-configured only in reactive (Webflux) applications and only if some {@link RestProperties} are present /!\</b>
 * </p>
 *
 * @author Jerome Wacongne chl4mp&#64;c4-soft.com
 * @see SpringAddonsRestClientSupport an equivalent for servlet (WebMVC) applications (configuring both {@link WebClient} and {@link RestClient})
 */
@Data
public class ReactiveSpringAddonsRestSupport {

    private final SpringAddonsOidcClientProperties addonsProperties;

    private final ReactiveOAuth2AuthorizedClientManager authorizedClientManager;

    /**
     * A {@link BearerProvider} to get the Bearer from the request security context
     */
    private final BearerProvider forwardingBearerProvider;

    /**
     * @param clientName key in "rest" entries of {@link SpringAddonsOidcClientProperties}
     * @return A {@link WebClient} Builder pre-configured with a base-URI and (optionally) with a Bearer Authorization
     */
    public WebClient.Builder webClientBuilder(String clientName) {
        final var clientProps = Optional
            .ofNullable(addonsProperties.getRest().get(clientName))
            .orElseThrow(() -> new RestConfigurationNotFoundException(clientName));
        if (clientProps.getAuth2RegistrationId().isPresent() && clientProps.isForwardBearer()) {
            throw new RestMisconfigurationConfigurationException(clientName);
        }

        final var clientBuilder = WebClient.builder().baseUrl(clientProps.getBaseUri().toString());
        clientProps.getAuth2RegistrationId().ifPresent(registrationId -> {
            clientBuilder.filter((ClientRequest request, ExchangeFunction next) -> {
                final var provider = new ReactiveAuthorizedClientBearerProvider(authorizedClientManager, registrationId);
                return provider.getBearer().defaultIfEmpty("").flatMap(bearer -> {
                    if (StringUtils.hasText(bearer)) {
                        request.headers().setBearerAuth(bearer);
                    }
                    return next.exchange(request);
                });
            });
        });
        if (clientProps.isForwardBearer()) {
            clientBuilder.filter((ClientRequest request, ExchangeFunction next) -> {
                final var bearer = forwardingBearerProvider.getBearer();
                bearer.ifPresent(request.headers()::setBearerAuth);
                return next.exchange(request);
            });
        }

        return clientBuilder;
    }

    /**
     * Uses the provided {@link WebClient} to proxy the httpServiceClass
     *
     * @param <T>
     * @param client
     * @param httpServiceClass class of the #64;Service (with {@link HttpExchange} methods) to proxy with a {@link WebClient}
     * @return a #64;Service proxy with a {@link WebClient}
     */
    public <T> T webClientService(WebClient client, Class<T> httpServiceClass) {
        return HttpServiceProxyFactory.builderFor(WebClientAdapter.create(client)).build().createClient(httpServiceClass);
    }

    /**
     * Builds a {@link WebClient} with just the provided spring-addons {@link RestProperties} and uses it to proxy the httpServiceClass.
     *
     * @param <T>
     * @param httpServiceClass class of the #64;Service (with {@link HttpExchange} methods) to proxy with a {@link WebClient}
     * @param clientName key in "rest" entries of spring-addons client properties
     * @return a #64;Service proxy with a {@link WebClient}
     */
    public <T> T webClientService(String clientName, Class<T> httpServiceClass) {
        return this.webClientService(this.webClientBuilder(clientName).build(), httpServiceClass);
    }

    /**
     * A {@link ClientHttpRequestInterceptor} adding a Bearer Authorization header (if the {@link OAuth2AuthorizedClientManager} provides one for the configured
     * registration ID).
     *
     * @author Jerome Wacongne ch4mp&#64;c4-soft.com
     */
    @Data
    @EqualsAndHashCode(callSuper = false)
    public class ReactiveAuthorizedClientBearerProvider implements ReactiveBearerProvider {
        private static final AnonymousAuthenticationToken ANONYMOUS = new AnonymousAuthenticationToken(
            "anonymous",
            "anonymous",
            List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS")));

        private final ReactiveOAuth2AuthorizedClientManager authorizedClientManager;
        private final String registrationId;

        @Override
        public Mono<String> getBearer() {
            final var authentication = Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication()).orElse(ANONYMOUS);
            OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(registrationId).principal(authentication).build();
            final var authorizedClient = authorizedClientManager.authorize(authorizeRequest);
            final var token = authorizedClient.map(OAuth2AuthorizedClient::getAccessToken);
            return token.map(OAuth2AccessToken::getTokenValue);
        }
    }

    public static class RestConfigurationNotFoundException extends RuntimeException {
        private static final long serialVersionUID = -1174591896184901571L;

        public RestConfigurationNotFoundException(String clientName) {
            super("No spring-addons OAuth2 client properties for a REST client named %s".formatted(clientName));
        }
    }

    public static class RestMisconfigurationConfigurationException extends RuntimeException {
        private static final long serialVersionUID = 681577983030933423L;

        public RestMisconfigurationConfigurationException(String clientName) {
            super("REST OAuth2 configuration for %s can be made with a registration ID or Bearer forwarding, but not both at a time".formatted(clientName));
        }
    }
}
