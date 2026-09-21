package com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
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
	 * The resource server auto-configuration references Spring Boot's
	 * {@link OAuth2ResourceServerProperties} in a bean signature: without this condition, an application
	 * with the Spring Security resource server jar but not the Boot class (always the case on Boot 4,
	 * where it lives in a dedicated module; a class-path oddity on Boot 3, where it ships with
	 * spring-boot-autoconfigure) would fail with a {@code NoClassDefFoundError} while the conditions are
	 * evaluated.
	 */
	@ConditionalOnClass(OAuth2ResourceServerProperties.class)
	static class ResourceServerAutoConfigurationIsOnClassPath {
	}

}
