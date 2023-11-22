package com.c4_soft.springaddons.security.oidc.starter.properties;

import java.net.URI;

import org.springframework.security.oauth2.core.oidc.StandardClaimNames;

import lombok.Data;

/**
 * OpenID Providers configuration. A minimum of one issuer is required. <b>Properties defined here are a replacement for
 * spring.security.oauth2.resourceserver.jwt.*</b> (which will be ignored). Authorities mapping defined here is used by both client and resource server
 * filter-chains.
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Data
public class OpenidProviderProperties {
	/**
	 * <p>
	 * Must be exactly the same as in access tokens (even trailing slash, if any, is important). In case of doubt, open one of your access tokens with a tool
	 * like <a href="https://jwt.io">https://jwt.io</a>.
	 * <p>
	 */
	private URI iss;

	/**
	 * Can be omitted if OpenID configuration can be retrieved from ${iss}/.well-known/openid-configuration
	 */
	private URI jwkSetUri;

	/**
	 * Can be omitted. Will insert an audience validator if not null or empty
	 */
	private String aud;

	/**
	 * Authorities mapping configuration, per claim
	 */
	private SimpleAuthoritiesMappingProperties[] authorities = { new SimpleAuthoritiesMappingProperties() };

	/**
	 * JSON path for the claim to use as "name" source
	 */
	private String usernameClaim = StandardClaimNames.SUB;
}