package com.c4_soft.springaddons.security.oauth2.config;

import java.net.URI;

import org.springframework.security.oauth2.client.registration.ClientRegistration;

/**
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public interface LogoutRequestUriBuilder {

	String getLogoutRequestUri(ClientRegistration clientRegistration, String idToken);

	String getLogoutRequestUri(ClientRegistration clientRegistration, String idToken, URI postLogoutUri);
}