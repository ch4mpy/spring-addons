package com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerProperties;
import org.springframework.security.oauth2.server.resource.web.HeaderBearerTokenResolver;

public class IsOidcResourceServerCondition extends AllNestedConditions {

	IsOidcResourceServerCondition() {
		super(ConfigurationPhase.PARSE_CONFIGURATION);
	}

	@ConditionalOnProperty(prefix = "com.c4-soft.springaddons.oidc.resourceserver", name = "enabled", matchIfMissing = true)
	static class SpringAddonsResourceServerEnabled {
	}

	@ConditionalOnClass(HeaderBearerTokenResolver.class)
	static class BearerTokenAuthenticationFilterIsOnClassPath {
	}

	/**
	 * The Spring Security jar is not enough: the resource server auto-configuration references Spring
	 * Boot's {@link OAuth2ResourceServerProperties} in a bean signature. Without this condition, an
	 * application with only {@code spring-security-oauth2-resource-server} on its class-path (pulled
	 * transitively, for instance by {@code spring-addons-starter-oidc-test} in an OAuth2 client) fails
	 * to start with a {@code NoClassDefFoundError} while the conditions are evaluated.
	 */
	@ConditionalOnClass(OAuth2ResourceServerProperties.class)
	static class ResourceServerAutoConfigurationIsOnClassPath {
	}

}
