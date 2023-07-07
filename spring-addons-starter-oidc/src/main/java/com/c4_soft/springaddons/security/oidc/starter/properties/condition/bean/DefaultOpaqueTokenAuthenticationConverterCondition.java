package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Conditional;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenAuthenticationConverter;

import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsOidcResourceServerCondition;

public class DefaultOpaqueTokenAuthenticationConverterCondition extends AllNestedConditions {
	DefaultOpaqueTokenAuthenticationConverterCondition() {
		super(ConfigurationPhase.REGISTER_BEAN);
	}

	@Conditional(IsOidcResourceServerCondition.class)
	static class SpringAddonsOidcResourceServerEnabled {
	}

	@Conditional(IsIntrospectingResourceServerCondition.class)
	static class SpringAddonsIntrospectionPropertiesPresent {
	}

	@ConditionalOnMissingBean(OpaqueTokenAuthenticationConverter.class)
	static class CustomAuthenticationConverterNotProvided {
	}

	@ConditionalOnMissingBean(ReactiveOpaqueTokenAuthenticationConverter.class)
	static class CustomReactiveAuthenticationConverterNotProvided {
	}
}