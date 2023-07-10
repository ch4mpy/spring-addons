package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.boot.autoconfigure.condition.AnyNestedCondition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

public class IsIntrospectingResourceServerCondition extends AnyNestedCondition {

	IsIntrospectingResourceServerCondition() {
		super(ConfigurationPhase.REGISTER_BEAN);
	}

	@ConditionalOnProperty("spring.security.oauth2.resourceserver.opaquetoken.introspection-uri")
	static class IsOpaqueTokenIntrospectionUriDeclared {
	}

}