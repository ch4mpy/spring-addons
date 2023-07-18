package com.c4_soft.springaddons.security.oidc.starter.properties;

import java.net.URI;
import java.util.Optional;

import lombok.Data;

/**
 * Logout properties for OpenID Providers which do not implement the RP-Initiated Logout spec
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Data
public class OAuth2LogoutProperties {

	/**
	 * URI on the authorization server where to redirect the user for logout
	 */
	private URI uri;

	/**
	 * request param name for client-id
	 */
	private Optional<String> clientIdRequestParam = Optional.empty();

	/**
	 * request param name for post-logout redirect URI (where the user should be redirected after his session is closed on the authorization server)
	 */
	private Optional<String> postLogoutUriRequestParam = Optional.empty();

	/**
	 * request param name for setting an ID-Token hint
	 */
	private Optional<String> idTokenHintRequestParam = Optional.empty();
}