package com.c4_soft.springaddons.security.oauth2.config;

import java.net.URI;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Data;

/**
 *
 * @author ch4mp
 */
@Data
@AutoConfiguration
@ConfigurationProperties(prefix = "com.c4-soft.springaddons.security.client")
public class SpringAddonsOAuth2ClientProperties {
    private URI postLogoutRedirectUri;
    private OAuth2LogoutProperties[] oauth2Logout = {};

    @Data
    public static class OAuth2LogoutProperties {
        private URI issuer;
        private URI uri;
        private String clientIdArgument = "client_id";
        private String postLogoutArgument;
    }
}