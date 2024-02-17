package com.c4_soft.springaddons.security.oidc.starter;

import java.net.URI;
import java.util.Optional;

import org.springframework.security.oauth2.client.registration.ClientRegistration;

/**
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public interface LogoutRequestUriBuilder {

    Optional<String> getLogoutRequestUri(ClientRegistration clientRegistration, String idToken);

    Optional<String> getLogoutRequestUri(ClientRegistration clientRegistration, String idToken, Optional<URI> postLogoutUri);
}
