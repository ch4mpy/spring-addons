package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import java.net.URI;
import java.nio.charset.StandardCharsets;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.RequiredArgsConstructor;

/**
 * Provide with pseudo RP initiated logout for authorization-servers "almost"
 * implementing OIDC standard
 *
 * @author ch4mp
 *
 */
@Data
@RequiredArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class OAuth2LogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final URI logoutUri;
    private final String clientIdParamName;
    private final String postLogoutParamName;
    private final URI postLogoutRedirectUri;

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) {
        String registrationId = ((OAuth2AuthenticationToken) authentication)
                .getAuthorizedClientRegistrationId();
        ClientRegistration clientRegistration = this.clientRegistrationRepository
                .findByRegistrationId(registrationId);
        final var builder = UriComponentsBuilder.fromUri(logoutUri).queryParam(clientIdParamName,
                clientRegistration.getClientId());
        if (StringUtils.hasText(postLogoutParamName)) {
            builder.queryParam(postLogoutParamName, postLogoutRedirectUri);
        }

        return builder.encode(StandardCharsets.UTF_8).build().toUriString();
    }
}