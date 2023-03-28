package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import java.net.URI;

import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.web.util.UriComponentsBuilder;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsOAuth2ClientProperties;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Forces the usage of {@link SpringAddonsOAuth2ClientProperties#getClientUri()
 * SpringAddonsOAuth2ClientProperties#client-uri} in post-login redirection URI
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 *
 */
public class SpringAddonsOAuth2AuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private final OAuth2AuthorizationRequestResolver defaultResolver;

    public SpringAddonsOAuth2AuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository) {
        defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository,
                OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        return toAbsolute(defaultResolver.resolve(request), request);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        return toAbsolute(defaultResolver.resolve(request, clientRegistrationId), request);
    }

    private OAuth2AuthorizationRequest toAbsolute(OAuth2AuthorizationRequest defaultAuthorizationRequest,
            HttpServletRequest request) {
        final var clientUriString = request.getRequestURL();
        if (defaultAuthorizationRequest == null || clientUriString == null) {
            return defaultAuthorizationRequest;
        }
        final var clientUri = URI.create(clientUriString.toString());
        final var redirectUri = UriComponentsBuilder.fromUriString(defaultAuthorizationRequest.getRedirectUri())
                .scheme(clientUri.getScheme()).host(clientUri.getHost())
                .port(clientUri.getPort()).build().toUriString();
        return OAuth2AuthorizationRequest.from(defaultAuthorizationRequest).redirectUri(redirectUri).build();
    }
}