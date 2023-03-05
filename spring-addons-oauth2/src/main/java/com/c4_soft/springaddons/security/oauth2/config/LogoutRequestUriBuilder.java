package com.c4_soft.springaddons.security.oauth2.config;

import java.net.URI;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;

/**
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 *
 */
public interface LogoutRequestUriBuilder {

    String getLogoutRequestUri(OAuth2AuthorizedClient authorizedClient, String idToken);

    String getLogoutRequestUri(OAuth2AuthorizedClient authorizedClient, String idToken, URI postLogoutUri);
}