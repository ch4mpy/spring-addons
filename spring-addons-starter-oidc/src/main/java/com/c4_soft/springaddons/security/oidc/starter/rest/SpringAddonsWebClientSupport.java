package com.c4_soft.springaddons.security.oidc.starter.rest;

import java.util.Optional;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.support.WebClientAdapter;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties.RestProperties;

import lombok.Data;

/**
 * <p>
 * Helps building {@link WebClient} instances. Main features are:
 * </p>
 * <ul>
 * <li>providing with builders pre-configured for OAuth2: add a Bearer Authorization header provided by the {@link OAuth2AuthorizedClientManager} for a given
 * registration-id or by a {@link BearerProvider} (taking the Bearer from the security context to forward it)</li>
 * <li>providing with helper methods to get a HTTP service from the {@link HttpServiceProxyFactory} and application properties</li>
 * </ul>
 * <p>
 * <p>
 * When spring-addons {@link RestProperties#forwardBearer} is true, the Bearer is taken from the {@link BearerProvider} in the context,
 * {@link DefaultBearerProvider} by default which works only with {@link JwtAuthenticationToken} or {@link BearerTokenAuthentication}. You must provide with
 * your own {@link BearerProvider} bean if your security configuration populates the security context with something else.
 * </p>
 * <p>
 * <b>/!\ Auto-configured only in servlet (WebMVC) applications and only if some {@link RestProperties} are present /!\</b>
 * </p>
 *
 * @author Jerome Wacongne chl4mp&#64;c4-soft.com
 * @see ReactiveSpringAddonsRestSupport an equivalent for reactive (Webflux) applications
 */
@Data
public class SpringAddonsWebClientSupport {

    private final SpringAddonsOidcClientProperties addonsProperties;

    private final OAuth2AuthorizedClientManager authorizedClientManager;

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
                final var provider = new AuthorizedClientBearerProvider(authorizedClientManager, registrationId);
                provider.getBearer().ifPresent(bearer -> {
                    request.headers().setBearerAuth(bearer);
                });
                return next.exchange(request);
            });
        });
        if (clientProps.isForwardBearer()) {
            clientBuilder.filter((ClientRequest request, ExchangeFunction next) -> {
                forwardingBearerProvider.getBearer().ifPresent(bearer -> {
                    request.headers().setBearerAuth(bearer);
                });
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
}
