package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.NoneNestedConditions;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;

public class DefaultAuthenticationEntryPointCondition extends NoneNestedConditions {

	public DefaultAuthenticationEntryPointCondition() {
		super(ConfigurationPhase.REGISTER_BEAN);
	}

	@ConditionalOnBean(AuthenticationEntryPoint.class)
	static class AuthenticationEntryPointCondition {
	}

	@ConditionalOnBean(ServerAuthenticationEntryPoint.class)
	static class ServerAuthenticationEntryPointCondition {
	}
}
