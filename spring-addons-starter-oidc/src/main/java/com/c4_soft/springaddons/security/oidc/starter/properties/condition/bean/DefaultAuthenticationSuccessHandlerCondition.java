package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.NoneNestedConditions;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public class DefaultAuthenticationSuccessHandlerCondition extends NoneNestedConditions {

	public DefaultAuthenticationSuccessHandlerCondition() {
		super(ConfigurationPhase.REGISTER_BEAN);
	}

	@ConditionalOnBean(AuthenticationSuccessHandler.class)
	static class AuthenticationSuccessHandlerProvidedCondition {
	}

	@ConditionalOnBean(AuthenticationSuccessHandler.class)
	static class ServerAuthenticationSuccessHandlerProvidedCondition {
	}
}
