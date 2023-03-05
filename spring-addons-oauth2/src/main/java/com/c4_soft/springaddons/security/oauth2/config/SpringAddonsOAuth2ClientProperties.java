package com.c4_soft.springaddons.security.oauth2.config;

import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.web.util.UriComponentsBuilder;

import lombok.Data;

/**
 * Properties to push one step further the auto-configuration of Spring Boot
 * OAuth2 clients
 *
 * @author ch4mp
 */
@Data
@AutoConfiguration
@ConfigurationProperties(prefix = "com.c4-soft.springaddons.security.client")
public class SpringAddonsOAuth2ClientProperties {
    /**
     * Fully qualified URI of the configured OAuth2 client.
     */
    private URI clientUri;

    /**
     * Path (relative to clientUri) where the user should be redirected after being
     * logged out from authorization server(s)
     */
    private String postLogoutRedirectPath;

    /**
     * Configuration for authorization server not following the <a href=
     * "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated
     * Logout</a>
     * standard, but exposing a logout end-point expecting an authorized GET request
     * with following request params:
     * <ul>
     * <li>"client-id" (required)</li>
     * <li>post-logout redirect URI (optional)</li>
     * </il>
     */
    private OAuth2LogoutProperties[] oauth2Logout = {};

    @Data
    public static class OAuth2LogoutProperties {
        /**
         * client registration id as set in Spring Boot OAuth2 client properties
         */
        private String clientRegistrationId;

        /**
         * URI on the authorization server where to redirect the user for logout
         */
        private URI uri;

        /**
         * request param name for client-id
         */
        private Optional<String> clientIdRequestParam = Optional.empty();

        /**
         * request param name for post-logout redirect URI (where the user should be
         * redirected after his session is closed on the authorization server)
         */
        private Optional<String> postLogoutUriRequestParam = Optional.empty();

        /**
         * request param name for setting an ID-Token hint
         */
        private Optional<String> idTokenHintRequestParam = Optional.empty();
    }

    public URI getPostLogoutRedirectUri() {
        return UriComponentsBuilder.fromUri(clientUri).path(postLogoutRedirectPath).build(Map.of());
    }

    public Optional<OAuth2LogoutProperties> getLogoutProperties(String clientRegistrationId) {
        return Stream.of(oauth2Logout).filter(logoutProps -> Objects
                .equals(clientRegistrationId, logoutProps.getClientRegistrationId()))
                .findAny();
    }
}