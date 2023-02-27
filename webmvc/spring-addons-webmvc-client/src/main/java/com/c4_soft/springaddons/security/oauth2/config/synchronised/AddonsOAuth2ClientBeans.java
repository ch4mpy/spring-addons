package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import java.io.IOException;
import java.net.URI;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsOAuth2ClientProperties;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;

/**
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@AutoConfiguration
@Import({ SpringAddonsOAuth2ClientProperties.class })
public class AddonsOAuth2ClientBeans {

    /**
     * Logout handler delegating to:
     * <ul>
     * <li>{@link OAuth2LogoutSuccessHandler} if
     * {@link SpringAddonsOAuth2ClientProperties} where registered for current
     * authorized client issuer</li>
     * <li>{@link OidcClientInitiatedLogoutSuccessHandler} otherwise (requires
     * authorization-server to be compliant with OIDC "RP initiated logout"
     * specification)</li>
     * </ul>
     *
     * @author ch4mp
     *
     */
    @Component
    @Data
    public static class C4LogoutSuccessHandler implements LogoutSuccessHandler {

        private final ClientRegistrationRepository clientRegistrationRepository;
        private final OidcClientInitiatedLogoutSuccessHandler oidcHandler;
        private final Map<String, LogoutSuccessHandler> oauth2Handlers;

        public C4LogoutSuccessHandler(
                ClientRegistrationRepository clientRegistrationRepository,
                SpringAddonsOAuth2ClientProperties clientProps) {
            this.clientRegistrationRepository = clientRegistrationRepository;

            this.oidcHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
            Optional.ofNullable(clientProps.getPostLogoutRedirectUri()).map(URI::toString)
                    .ifPresent(oidcHandler::setPostLogoutRedirectUri);

            this.oauth2Handlers = Stream.of(clientProps.getOauth2Logout()).collect(
                    Collectors.toMap(
                            props -> props.getIssuer().toString(),
                            props -> new OAuth2LogoutSuccessHandler(
                                    clientRegistrationRepository,
                                    props.getUri(),
                                    props.getClientIdArgument(),
                                    props.getPostLogoutArgument(),
                                    clientProps.getPostLogoutRedirectUri())));
        }

        @Override
        public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                Authentication authentication) throws IOException, ServletException {
            final var registrationId = ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId();
            final var clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
            final var issuer = clientRegistration.getProviderDetails().getConfigurationMetadata().get("issuer")
                    .toString();
            final var handler = oauth2Handlers.getOrDefault(issuer, oidcHandler);

            handler.onLogoutSuccess(request, response, authentication);
        }
    }
}