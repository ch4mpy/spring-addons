package com.c4_soft.springaddons.rest;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import java.util.regex.Pattern;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.support.RestClientAdapter;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;

import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.ClientProperties.AuthorizationProperties;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

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
 * When spring-addons {@link SpringAddonsRestProperties.ClientProperties.AuthorizationProperties.OAuth2Properties#forwardBearer} is true, the Bearer is taken
 * from the {@link BearerProvider} in the context, {@link DefaultBearerProvider} by default which works only with {@link JwtAuthenticationToken} or
 * {@link BearerTokenAuthentication}. You must provide with your own {@link BearerProvider} bean if your security configuration populates the security context
 * with something else.
 * </p>
 * <p>
 * <b>/!\ Auto-configured only in servlet (WebMVC) applications and only if some {@link SpringAddonsRestProperties} are present /!\</b>
 * </p>
 *
 * @author Jerome Wacongne chl4mp&#64;c4-soft.com
 */
@Data
@Slf4j
public class SpringAddonsRestClientSupport {

    private final SpringAddonsRestProperties addonsProperties;

    /**
     * A {@link BearerProvider} to get the Bearer from the request security context
     */
    private final BearerProvider forwardingBearerProvider;

    private final Optional<OAuth2AuthorizedClientManager> authorizedClientManager;

    public RestClient.Builder client() {
        final var builder = RestClient.builder();
        addonsProperties
            .getProxy()
            .getHostname()
            .map(proxyHostname -> new SpringAddonsClientHttpRequestFactory(addonsProperties.getProxy()))
            .ifPresent(builder::requestFactory);
        if (addonsProperties.getProxy().isEnabled() && StringUtils.hasText(addonsProperties.getProxy().getUsername()) && StringUtils
            .hasText(addonsProperties.getProxy().getPassword())) {
            final var base64 = Base64
                .getEncoder()
                .encodeToString((addonsProperties.getProxy().getUsername() + ':' + addonsProperties.getProxy().getPassword()).getBytes(StandardCharsets.UTF_8));
            builder.defaultHeader(HttpHeaders.PROXY_AUTHORIZATION, "Basic %s".formatted(base64));
        }

        return builder;
    }

    /**
     * @param clientName key in "client" entries of {@link SpringAddonsRestProperties}
     * @return A {@link RestClient} Builder pre-configured with a base-URI and (optionally) with a Bearer Authorization
     */
    public RestClient.Builder client(String clientName) {
        final var clientProps = Optional
            .ofNullable(addonsProperties.getClient().get(clientName))
            .orElseThrow(() -> new RestConfigurationNotFoundException(clientName));

        final var clientBuilder = client();

        clientProps.getBaseUrl().map(URL::toString).ifPresent(clientBuilder::baseUrl);

        authorize(clientBuilder, clientProps.getAuthorization(), clientName);

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
    public <T> T service(RestClient client, Class<T> httpServiceClass) {
        return HttpServiceProxyFactory.builderFor(RestClientAdapter.create(client)).build().createClient(httpServiceClass);
    }

    /**
     * Builds a {@link RestClient} with just the provided spring-addons {@link SpringAddonsRestProperties} and uses it to proxy the httpServiceClass.
     *
     * @param <T>
     * @param httpServiceClass class of the #64;Service (with {@link HttpExchange} methods) to proxy with a {@link RestClient}
     * @param clientName key in "client" entries of {@link SpringAddonsRestProperties}
     * @return a #64;Service proxy with a {@link RestClient}
     */
    public <T> T service(String clientName, Class<T> httpServiceClass) {
        return this.service(this.client(clientName).build(), httpServiceClass);
    }

    protected void authorize(RestClient.Builder clientBuilder, AuthorizationProperties authProps, String clientName) {
        if (authProps.getOauth2().isConfigured() && authProps.getBasic().isConfigured()) {
            throw new RestMisconfigurationConfigurationException(
                "REST authorization configuration for %s can be made for either OAuth2 or Basic, but not both at a time".formatted(clientName));
        }
        if (authProps.getOauth2().isConfigured()) {
            oauth2(clientBuilder, authProps.getOauth2(), clientName);
        } else if (authProps.getBasic().isConfigured()) {
            basic(clientBuilder, authProps.getBasic(), clientName);
        }
    }

    protected void oauth2(RestClient.Builder clientBuilder, AuthorizationProperties.OAuth2Properties oauth2Props, String clientName) {
        if (!oauth2Props.isConfValid()) {
            throw new RestMisconfigurationConfigurationException(
                "REST OAuth2 authorization configuration for %s can be made for either a registration-id or resource server Bearer forwarding, but not both at a time"
                    .formatted(clientName));
        }
        oauth2Props.getOauth2RegistrationId().flatMap(this::oauth2RequestInterceptor).ifPresent(clientBuilder::requestInterceptor);
        if (oauth2Props.isForwardBearer()) {
            clientBuilder.requestInterceptor((request, body, execution) -> {
                forwardingBearerProvider.getBearer().ifPresent(bearer -> {
                    request.getHeaders().setBearerAuth(bearer);
                });
                return execution.execute(request, body);
            });
        }
    }

    protected Optional<ClientHttpRequestInterceptor> oauth2RequestInterceptor(String registrationId) {
        if (authorizedClientManager.isEmpty()) {
            log.warn("OAuth2 client missconfiguration. Can't setup an OAuth2 Bearer request interceptor because there is no authorizedClientManager bean.");
        }
        return authorizedClientManager.map(acm -> (request, body, execution) -> {
            final var provider = new AuthorizedClientBearerProvider(acm, registrationId);
            provider.getBearer().ifPresent(bearer -> {
                request.getHeaders().setBearerAuth(bearer);
            });
            return execution.execute(request, body);
        });
    }

    protected void basic(RestClient.Builder clientBuilder, AuthorizationProperties.BasicAuthProperties authProps, String clientName) {
        if (authProps.getEncodedCredentials().isPresent()) {
            if (authProps.getUsername().isPresent() || authProps.getPassword().isPresent() || authProps.getCharset().isPresent()) {
                throw new RestMisconfigurationConfigurationException(
                    "REST Basic authorization for %s is misconfigured: when encoded-credentials is provided, username, password and charset must be absent."
                        .formatted(clientName));
            }
        } else {
            if (authProps.getUsername().isEmpty() || authProps.getPassword().isEmpty()) {
                throw new RestMisconfigurationConfigurationException(
                    "REST Basic authorization for %s is misconfigured: when encoded-credentials is empty, username & password are required."
                        .formatted(clientName));
            }
        }
        clientBuilder.requestInterceptor((request, body, execution) -> {
            authProps.getEncodedCredentials().ifPresent(request.getHeaders()::setBasicAuth);
            authProps
                .getCharset()
                .ifPresentOrElse(
                    charset -> request.getHeaders().setBasicAuth(authProps.getUsername().get(), authProps.getPassword().get(), charset),
                    () -> request.getHeaders().setBasicAuth(authProps.getUsername().get(), authProps.getPassword().get()));
            return execution.execute(request, body);
        });
    }

    static Proxy.Type protocoleToProxyType(String protocol) {
        if (protocol == null) {
            return null;
        }
        final var lower = protocol.toLowerCase();
        if (lower.startsWith("http")) {
            return Proxy.Type.HTTP;
        }
        if (lower.startsWith("socks")) {
            return Proxy.Type.SOCKS;
        }
        return null;
    }

    static class SpringAddonsClientHttpRequestFactory extends SimpleClientHttpRequestFactory {
        private final Optional<Pattern> nonProxyHostsPattern;
        private final Optional<Proxy> proxyOpt;

        public SpringAddonsClientHttpRequestFactory(SpringAddonsRestProperties.ProxyProperties proxyProperties) {
            super();
            this.nonProxyHostsPattern = Optional.ofNullable(proxyProperties.getNoProxy()).map(Pattern::compile);

            this.proxyOpt = proxyProperties.getHostname().map(proxyHostname -> {
                final var address = new InetSocketAddress(proxyHostname, proxyProperties.getPort());
                return new Proxy(protocoleToProxyType(proxyProperties.getProtocol()), address);
            });

            setConnectTimeout(proxyProperties.getConnectTimeoutMillis());
        }

        @Override
        public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) throws IOException {
            super.setProxy(proxyOpt.filter(proxy -> {
                return nonProxyHostsPattern.map(pattern -> !pattern.matcher(uri.getHost()).matches()).orElse(true);
            }).orElse(null));
            return super.createRequest(uri, httpMethod);
        }

    }
}
