package com.c4_soft.springaddons.security.oidc.starter.properties;

import java.net.URI;

import org.springframework.boot.context.properties.NestedConfigurationProperty;
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
	 * Can be omitted if jwk-set-uri is provided. Will insert an issuer validator if not null or empty. It must be exactly the same as in access tokens (even
	 * trailing slash, if any, is important). In case of doubt, open one of your access tokens with a tool like https://jwt.io
	 */
	private URI iss;

	/**
	 * Can be omitted if issuer-uri is provided
	 */
	private URI jwkSetUri;

	/**
	 * Can be omitted. Will insert an audience validator if not null or empty
	 */
	private String aud;

	/**
	 * Authorities mapping configuration, per claim
	 */
	@NestedConfigurationProperty
	private SimpleAuthoritiesMappingProperties[] authorities = { new SimpleAuthoritiesMappingProperties() };

	/**
	 * JSON path for the claim to use as "name" source
	 */
	private String usernameClaim = StandardClaimNames.SUB;
}