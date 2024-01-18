package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.NoneNestedConditions;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;

public class DefaultAuthenticationFailureHandlerCondition extends NoneNestedConditions {

	public DefaultAuthenticationFailureHandlerCondition() {
		super(ConfigurationPhase.REGISTER_BEAN);
	}

	@ConditionalOnBean(AuthenticationFailureHandler.class)
	static class AuthenticationFailureHandlerProvidedCondition {
	}

	@ConditionalOnBean(ServerAuthenticationFailureHandler.class)
	static class ServerAuthenticationFailureHandlerProvidedCondition {
	}

}
