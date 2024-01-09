package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.net.URI;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties.RequestParam;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Support three features:
 * <ul>
 * <li>Use the {@link SpringAddonsOidcClientProperties#clientUri SpringAddonsOidcClientProperties#client-uri} to set the base URI of authorization-code callback
 * (of interest for instance when using an ingress or another gateway in front of the OAuth2 client with oauth2Login)</li>
 * <li>Defining authorization request additional parameters from properties (like audience for Auth0)</li>
 * <li>Save in session post-login URIs provided as header ({@link SpringAddonsOidcClientProperties#POST_AUTHENTICATION_SUCCESS_URI_HEADER} and
 * {@link SpringAddonsOidcClientProperties#POST_AUTHENTICATION_FAILURE_URI_HEADER}) or request param
 * ({@link SpringAddonsOidcClientProperties#POST_AUTHENTICATION_SUCCESS_URI_PARAM} and
 * {@link SpringAddonsOidcClientProperties#POST_AUTHENTICATION_FAILURE_URI_PARAM}). If both are provided, header wins. The key used in session are
 * {@link SpringAddonsOidcClientProperties#POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE} and
 * {@link SpringAddonsOidcClientProperties#POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE}</li>
 * </ul>
 * The post-login URIs are used by the default {@link AuthenticationSuccessHandler} and {@link AuthenticationFailureHandler}
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see SpringAddonsOidcClientProperties for header and request parameter constants definitions
 * @see SpringAddonsOauth2AuthenticationSuccessHandler
 * @see SpringAddonsOauth2AuthenticationFailureHandler
 */
public class SpringAddonsOAuth2AuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {
    private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";

    private final URI clientUri;
    private final DefaultOAuth2AuthorizationRequestResolver delegate;
    private final Map<String, Consumer<OAuth2AuthorizationRequest.Builder>> authRequestCustomizers;
    private final AntPathRequestMatcher authorizationRequestMatcher = new AntPathRequestMatcher(
        OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");

    public SpringAddonsOAuth2AuthorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository,
            SpringAddonsOidcClientProperties addonsClientProperties) {

        this.clientUri = addonsClientProperties.getClientUri();

        authRequestCustomizers = addonsClientProperties.getAuthorizationRequestParams().entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, e -> {
            final var params = addonsClientProperties.getAuthorizationRequestParams().get(e.getKey());
            return e.getValue() == null ? null : requestParamAuthorizationRequestCustomizer(params);
        }));

        delegate = new DefaultOAuth2AuthorizationRequestResolver(
            clientRegistrationRepository,
            OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
    }

    private Optional<String> getFirstParam(HttpServletRequest request, String paramName) {
        final var values = request.getParameterValues(paramName);
        if (values == null || values.length < 1) {
            return Optional.empty();
        }
        return Optional.of(values[0]);
    }

    private void savePostLoginUrisInSession(HttpServletRequest request) {
        final var session = request.getSession();
        Optional
            .ofNullable(
                Optional
                    .ofNullable(request.getHeader(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER))
                    .orElse(getFirstParam(request, SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_PARAM).orElse(null)))
            .filter(StringUtils::hasText)
            .map(URI::create)
            .ifPresent(postLoginSuccessUri -> {
                session.setAttribute(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE, postLoginSuccessUri);
            });

        Optional
            .ofNullable(
                Optional
                    .ofNullable(request.getHeader(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_HEADER))
                    .orElse(getFirstParam(request, SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_PARAM).orElse(null)))
            .filter(StringUtils::hasText)
            .map(URI::create)
            .ifPresent(postLoginFailureUri -> {
                session.setAttribute(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE, postLoginFailureUri);
            });
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        savePostLoginUrisInSession(request);
        final var registrationId = resolveRegistrationId(request);
        delegate.setAuthorizationRequestCustomizer(authRequestCustomizers.getOrDefault(registrationId, b -> {}));
        final var resolved = delegate.resolve(request);
        final var absolute = toAbsolute(resolved, request);
        return absolute;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        savePostLoginUrisInSession(request);
        delegate.setAuthorizationRequestCustomizer(authRequestCustomizers.getOrDefault(clientRegistrationId, b -> {}));
        final var resolved = delegate.resolve(request, clientRegistrationId);
        final var absolute = toAbsolute(resolved, request);
        return absolute;
    }

    private OAuth2AuthorizationRequest toAbsolute(OAuth2AuthorizationRequest defaultAuthorizationRequest, HttpServletRequest request) {
        final var requestUrl = request.getRequestURL();
        if (defaultAuthorizationRequest == null || requestUrl == null) {
            return defaultAuthorizationRequest;
        }

        final var original = URI.create(requestUrl.toString());
        final var redirectUri = UriComponentsBuilder
            .fromUri(clientUri)
            .path(original.getPath())
            .query(original.getQuery())
            .fragment(original.getFragment())
            .build()
            .toString();
        return OAuth2AuthorizationRequest
            .from(defaultAuthorizationRequest)
            .redirectUri(redirectUri)
            .authorizationRequestUri(defaultAuthorizationRequest.getAuthorizationRequestUri())
            .build();
    }

    private String resolveRegistrationId(HttpServletRequest request) {
        if (this.authorizationRequestMatcher.matches(request)) {
            return this.authorizationRequestMatcher.matcher(request).getVariables().get(REGISTRATION_ID_URI_VARIABLE_NAME);
        }
        return null;
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
