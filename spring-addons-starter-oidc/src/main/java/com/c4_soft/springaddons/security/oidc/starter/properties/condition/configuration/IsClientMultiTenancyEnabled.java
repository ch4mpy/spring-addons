package com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

public class IsClientMultiTenancyEnabled extends AllNestedConditions {

	public IsClientMultiTenancyEnabled() {
		super(ConfigurationPhase.PARSE_CONFIGURATION);
	}

	@ConditionalOnProperty(prefix = "com.c4-soft.springaddons.oidc.client", name = "multi-tenancy-enabled", matchIfMissing = false)
	static class IsMultiTenancyEnabled {
	}

}