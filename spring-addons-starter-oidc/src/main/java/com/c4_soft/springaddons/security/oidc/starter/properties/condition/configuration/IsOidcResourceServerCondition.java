package com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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

}