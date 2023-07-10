package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Conditional;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;

public class DefaultAuthenticationManagerResolverCondition extends AllNestedConditions {

	DefaultAuthenticationManagerResolverCondition() {
		super(ConfigurationPhase.REGISTER_BEAN);
	}

	@Conditional(IsJwtDecoderResourceServerCondition.class)
	static class IsJwtResourceServer {
	}

	@ConditionalOnMissingBean(AuthenticationManagerResolver.class)
	static class CustomAuthenticationManagerResolverNotProvided {
	}

	@ConditionalOnMissingBean(ReactiveAuthenticationManagerResolver.class)
	static class CustomReactiveAuthenticationManagerResolverNotProvided {
	}

}