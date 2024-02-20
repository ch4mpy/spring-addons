package com.c4_soft.springaddons.rest;

import java.util.List;
import java.util.Optional;

import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * Used by a {@link ClientHttpRequestInterceptor} to add a Bearer Authorization header (if the {@link OAuth2AuthorizedClientManager} provides one for the
 * configured registration ID).
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Data
@EqualsAndHashCode(callSuper = false)
public class AuthorizedClientBearerProvider implements BearerProvider {
    private static final AnonymousAuthenticationToken ANONYMOUS = new AnonymousAuthenticationToken(
        "anonymous",
        "anonymous",
        List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS")));

    private final OAuth2AuthorizedClientManager authorizedClientManager;
    private final String registrationId;

    @Override
    public Optional<String> getBearer() {
        final var authentication = Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication()).orElse(ANONYMOUS);
        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(registrationId).principal(authentication).build();
        final var authorizedClient = Optional.ofNullable(authorizedClientManager.authorize(authorizeRequest));
        final var token = authorizedClient.map(OAuth2AuthorizedClient::getAccessToken);
        return token.map(OAuth2AccessToken::getTokenValue);
    }
}
