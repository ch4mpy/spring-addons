package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Conditional;

import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsOidcResourceServerCondition;
import com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver.ReactiveJwtAbstractAuthenticationTokenConverter;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.JwtAbstractAuthenticationTokenConverter;

public class DefaultJwtAbstractAuthenticationTokenConverterCondition extends AllNestedConditions {
	DefaultJwtAbstractAuthenticationTokenConverterCondition() {
		super(ConfigurationPhase.REGISTER_BEAN);
	}

	@Conditional(IsOidcResourceServerCondition.class)
	static class SpringAddonsOidcClientEnabled {
	}

	@Conditional(IsJwtDecoderResourceServerCondition.class)
	static class SpringAddonsIntrospectionPropertiesPresent {
	}

	@ConditionalOnMissingBean(JwtAbstractAuthenticationTokenConverter.class)
	static class CustomAuthenticationConverterNotProvided {
	}

	@ConditionalOnMissingBean(ReactiveJwtAbstractAuthenticationTokenConverter.class)
	static class CustomReactiveAuthenticationConverterNotProvided {
	}
}