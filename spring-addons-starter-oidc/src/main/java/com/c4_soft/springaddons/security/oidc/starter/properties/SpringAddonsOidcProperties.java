package com.c4_soft.springaddons.security.oidc.starter.properties;

import java.net.URI;
import java.util.List;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;

import lombok.Data;

/**
 * <p>
 * Configuration properties for OAuth2 auto-configuration extensions to spring-boot-starter-oauth2-client and
 * spring-boot-starter-oauth2-resource-server.
 * </p>
 * The following spring-boot standard properties are used:
 * <ul>
 * <li>spring.security.oauth2.client.provider.*</li>
 * <li>spring.security.oauth2.client.registration.*</li>
 * <li>spring.security.oauth2.resourceserver.opaquetoken.*</li>
 * </ul>
 * <b>spring.security.oauth2.resourceserver.jwt.* properties are ignored.</b> The reason for that is it is applicable only to single tenant
 * scenarios. Use properties
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Data
@AutoConfiguration
@ConfigurationProperties(prefix = "com.c4-soft.springaddons.oidc")
public class SpringAddonsOidcProperties {

	/**
	 * OpenID Providers configuration: JWK set URI, issuer URI, audience, and authorities mapping configuration for each issuer. A minimum of
	 * one issuer is required. <b>Properties defined here are a replacement for spring.security.oauth2.resourceserver.jwt.*</b> (which will be
	 * ignored). Authorities mapping defined there is used by both client and resource server filter-chains.
	 */
	private List<OpenidProviderProperties> ops = List.of();

	/**
	 * Auto-configuration for an OAuth2 client (secured with session, not access token) Security(Web)FilterChain with
	 * &#64;Order(Ordered.LOWEST_PRECEDENCE - 1). Typical use-cases are spring-cloud-gateway used as BFF and applications with Thymeleaf or
	 * another server-side rendering framework. Default configuration includes: enabled sessions, CSRF protection, "oauth2Login", "logout".
	 * securityMatchers must be set for this filter-chain &#64;Bean and its dependencies to be defined. <b>Properties defined here are a
	 * complement for spring.security.oauth2.client.*</b> (which are required when enabling spring-addons client filter-chain).
	 */
	@NestedConfigurationProperty
	private SpringAddonsOidcClientProperties client = new SpringAddonsOidcClientProperties();

	/**
	 * Auto-configuration for an OAuth2 resource server Security(Web)FilterChain with &#64;Order(LOWEST_PRECEDENCE). Typical use case is a REST
	 * API secured with access tokens. Default configuration is as follow: no securityMatcher to process all the requests that were not
	 * intercepted by higher &#64;Order Security(Web)FilterChains, no session, disabled CSRF protection, and 401 to unauthorized requests.
	 */
	@NestedConfigurationProperty
	private SpringAddonsOidcResourceServerProperties resourceserver = new SpringAddonsOidcResourceServerProperties();

	/**
	 * OpenID Providers configuration. A minimum of one issuer is required. <b>Properties defined here are a replacement for
	 * spring.security.oauth2.resourceserver.jwt.*</b> (which will be ignored). Authorities mapping defined here is used by both client and
	 * resource server filter-chains.
	 *
	 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
	 */
	@Data
	@ConfigurationProperties
	static public class OpenidProviderProperties {
		/**
		 * <p>
		 * Must be exactly the same as in access tokens (even trailing slash, if any, is important). In case of doubt, open one of your access
		 * tokens with a tool like <a href="https://jwt.io">https://jwt.io</a>.
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
		private List<SimpleAuthoritiesMappingProperties> authorities = List.of();

		/**
		 * JSON path for the claim to use as "name" source
		 */
		private String usernameClaim = StandardClaimNames.SUB;

		@Data
		@ConfigurationProperties
		public static class SimpleAuthoritiesMappingProperties {
			/**
			 * JSON path of the claim(s) to map with this properties
			 */
			private String path = "$.realm_access.roles";

			/**
			 * What to prefix authorities with (for instance "ROLE_" or "SCOPE_")
			 */
			private String prefix = "";

			/**
			 * Whether to transform authorities to uppercase, lowercase, or to leave it unchanged
			 */
			private Case caze = Case.UNCHANGED;

			public static enum Case {
				UNCHANGED, UPPER, LOWER
			}

		}
	}
}
