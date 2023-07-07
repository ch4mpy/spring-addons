package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.NoneNestedConditions;

public class IsJwtDecoderResourceServerCondition extends NoneNestedConditions {

	IsJwtDecoderResourceServerCondition() {
		super(ConfigurationPhase.REGISTER_BEAN);
	}

	@ConditionalOnProperty("spring.security.oauth2.resourceserver.opaquetoken.introspection-uri")
	static class IsOpaqueTokenIntrospectionUriDeclared {
	}

}