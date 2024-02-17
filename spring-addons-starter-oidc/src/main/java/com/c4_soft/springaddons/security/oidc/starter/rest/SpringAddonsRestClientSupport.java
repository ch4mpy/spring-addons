package com.c4_soft.springaddons.security.oidc.starter.rest;

import java.util.Optional;

import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.support.RestClientAdapter;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties.RestProperties;

import lombok.Data;

/**
 * <p>
 * Helps building {@link RestClient} instances. Main features are:
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
public class SpringAddonsRestClientSupport {

    private final SpringAddonsOidcClientProperties addonsProperties;

    private final OAuth2AuthorizedClientManager authorizedClientManager;

    /**
     * A {@link BearerProvider} to get the Bearer from the request security context
     */
    private final BearerProvider forwardingBearerProvider;

    /**
     * @param clientName key in "rest" entries of {@link SpringAddonsOidcClientProperties}
     * @return A {@link RestClient} Builder pre-configured with a base-URI and (optionally) with a Bearer Authorization
     */
    public RestClient.Builder restClientBuilder(String clientName) {
        final var clientProps = Optional
            .ofNullable(addonsProperties.getRest().get(clientName))
            .orElseThrow(() -> new RestConfigurationNotFoundException(clientName));
        if (clientProps.getAuth2RegistrationId().isPresent() && clientProps.isForwardBearer()) {
            throw new RestMisconfigurationConfigurationException(clientName);
        }

        final var clientBuilder = RestClient.builder().baseUrl(clientProps.getBaseUri().toString());
        clientProps.getAuth2RegistrationId().ifPresent(registrationId -> {
            clientBuilder.requestInterceptor((HttpRequest request, byte[] body, ClientHttpRequestExecution execution) -> {
                final var provider = new AuthorizedClientBearerProvider(authorizedClientManager, registrationId);
                provider.getBearer().ifPresent(bearer -> {
                    request.getHeaders().setBearerAuth(bearer);
                });
                return execution.execute(request, body);
            });
        });
        if (clientProps.isForwardBearer()) {
            clientBuilder.requestInterceptor((HttpRequest request, byte[] body, ClientHttpRequestExecution execution) -> {
                forwardingBearerProvider.getBearer().ifPresent(bearer -> {
                    request.getHeaders().setBearerAuth(bearer);
                });
                return execution.execute(request, body);
            });
        }

        return clientBuilder;
    }

    /**
     * Uses the provided {@link RestClient} to proxy the httpServiceClass
     *
     * @param <T>
     * @param client
     * @param httpServiceClass class of the #64;Service (with {@link HttpExchange} methods) to proxy with a {@link RestClient}
     * @return a #64;Service proxy with a {@link RestClient}
     */
    public <T> T restClientService(RestClient client, Class<T> httpServiceClass) {
        return HttpServiceProxyFactory.builderFor(RestClientAdapter.create(client)).build().createClient(httpServiceClass);
    }

    /**
     * Builds a {@link RestClient} with just the provided spring-addons {@link RestProperties} and uses it to proxy the httpServiceClass.
     *
     * @param <T>
     * @param httpServiceClass class of the #64;Service (with {@link HttpExchange} methods) to proxy with a {@link RestClient}
     * @param clientName key in "rest" entries of {@link SpringAddonsOidcClientProperties}
     * @return a #64;Service proxy with a {@link RestClient}
     */
    public <T> T restClientService(String clientName, Class<T> httpServiceClass) {
        return this.restClientService(this.restClientBuilder(clientName).build(), httpServiceClass);
    }
}
