package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.net.URI;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import org.springframework.web.util.UriComponentsBuilder;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties.RequestParam;

import reactor.core.publisher.Mono;

/**
 * Serves three purposes:
 * <ul>
 * <li>Use the {@link SpringAddonsOidcClientProperties#clientUri SpringAddonsOidcClientProperties#client-uri} to set the base URI of authorization-code callback
 * (of interest for instance when using an ingress or another gateway in front of the OAuth2 client with oauth2Login)</li>
 * <li>Add the query params taken from authorization-request-params in application properties</li>
 * <li>Save in session post-login URIs provided as header ({@link SpringAddonsOidcClientProperties#POST_AUTHENTICATION_SUCCESS_URI_HEADER} and
 * {@link SpringAddonsOidcClientProperties#POST_AUTHENTICATION_FAILURE_URI_HEADER}) or request param
 * ({@link SpringAddonsOidcClientProperties#POST_AUTHENTICATION_SUCCESS_URI_PARAM} and
 * {@link SpringAddonsOidcClientProperties#POST_AUTHENTICATION_FAILURE_URI_PARAM}). If both are provided, header wins. The key used in session are
 * {@link SpringAddonsOidcClientProperties#POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE} and
 * {@link SpringAddonsOidcClientProperties#POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE}.</li>
 * </ul>
 * The post-login URIs are used by the default {@link ServerAuthenticationSuccessHandler} and {@link ServerAuthenticationFailureHandler}
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see SpringAddonsOidcClientProperties for header and request parameter constants definitions
 * @see SpringAddonsOauth2ServerAuthenticationSuccessHandler
 * @see SpringAddonsOauth2ServerAuthenticationFailureHandler
 */
public class SpringAddonsServerOAuth2AuthorizationRequestResolver extends DefaultServerOAuth2AuthorizationRequestResolver {

    private static final Pattern authorizationRequestPattern = Pattern.compile("\\/oauth2\\/authorization\\/([^\\/]+)");
    private static final Consumer<OAuth2AuthorizationRequest.Builder> noOpCustomizer = builder -> {};

    private final URI clientUri;
    private final Map<String, Consumer<OAuth2AuthorizationRequest.Builder>> authRequestCustomizers;

    public SpringAddonsServerOAuth2AuthorizationRequestResolver(
            ReactiveClientRegistrationRepository clientRegistrationRepository,
            SpringAddonsOidcClientProperties addonsClientProperties) {
        super(clientRegistrationRepository);
        this.clientUri = addonsClientProperties.getClientUri();
        authRequestCustomizers = addonsClientProperties.getAuthorizationRequestParams().entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, e -> {
            final var params = addonsClientProperties.getAuthorizationRequestParams().get(e.getKey());
            return e.getValue() == null ? null : requestParamAuthorizationRequestCustomizer(params);
        }));
    }

    private Mono<WebSession> savePostLoginUrisInSession(ServerWebExchange exchange) {
        return exchange.getSession().map(session -> {
            Optional
                .ofNullable(
                    Optional
                        .ofNullable(exchange.getRequest().getHeaders().getFirst(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER))
                        .orElse(
                            Optional
                                .ofNullable(
                                    exchange.getRequest().getQueryParams().getFirst(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_PARAM))
                                .orElse(null)))
                .filter(StringUtils::hasText)
                .map(URI::create)
                .ifPresent(postLoginSuccessUri -> {
                    session.getAttributes().put(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE, postLoginSuccessUri);
                });

            Optional
                .ofNullable(
                    Optional
                        .ofNullable(exchange.getRequest().getHeaders().getFirst(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_HEADER))
                        .orElse(
                            Optional
                                .ofNullable(
                                    exchange.getRequest().getQueryParams().getFirst(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_PARAM))
                                .orElse(null)))
                .filter(StringUtils::hasText)
                .map(URI::create)
                .ifPresent(postLoginFailureUri -> {
                    session.getAttributes().put(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE, postLoginFailureUri);
                });

            return session;
        });
    }

    private OAuth2AuthorizationRequest postProcess(OAuth2AuthorizationRequest request) {
        final var modified = OAuth2AuthorizationRequest.from(request);

        final var original = URI.create(request.getRedirectUri());
        final var redirectUri = UriComponentsBuilder
            .fromUri(clientUri)
            .path(original.getPath())
            .query(original.getQuery())
            .fragment(original.getFragment())
            .build()
            .toString();
        modified.redirectUri(redirectUri);

        return modified.build();
    }

    @Override
    public Mono<OAuth2AuthorizationRequest> resolve(ServerWebExchange exchange) {
        setAuthorizationRequestCustomizer(authRequestCustomizer(exchange));
        return savePostLoginUrisInSession(exchange).then(super.resolve(exchange).map(this::postProcess));
    }

    @Override
    public Mono<OAuth2AuthorizationRequest> resolve(ServerWebExchange exchange, String clientRegistrationId) {
        setAuthorizationRequestCustomizer(authRequestCustomizer(clientRegistrationId));
        return savePostLoginUrisInSession(exchange).then(super.resolve(exchange, clientRegistrationId).map(this::postProcess));
    }

    Consumer<OAuth2AuthorizationRequest.Builder> authRequestCustomizer(ServerWebExchange exchange) {
        return authRequestCustomizer(resolveRegistrationId(exchange));
    }

    Consumer<OAuth2AuthorizationRequest.Builder> authRequestCustomizer(String registrationId) {
        if (registrationId == null) {
            return noOpCustomizer;
        }
        return authRequestCustomizers.getOrDefault(registrationId, noOpCustomizer);
    }

    static String resolveRegistrationId(ServerWebExchange exchange) {
        final var requestPath = Optional.ofNullable(exchange.getRequest()).map(ServerHttpRequest::getPath).map(RequestPath::toString).orElse("");
        return resolveRegistrationId(requestPath);
    }

    static String resolveRegistrationId(String requestPath) {
        final var matcher = authorizationRequestPattern.matcher(requestPath);
        return matcher.matches() ? matcher.group(1) : null;
    }

    private static Consumer<OAuth2AuthorizationRequest.Builder> requestParamAuthorizationRequestCustomizer(RequestParam[] additionalParams) {
        return customizer -> customizer.authorizationRequestUri(authorizationRequestUri -> {
            for (var reqParam : additionalParams) {
                authorizationRequestUri.queryParam(reqParam.getName(), reqParam.getValue());
            }
            return authorizationRequestUri.build();
        });
    }

}
