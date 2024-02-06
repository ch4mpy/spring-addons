package com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;

public class IsReactiveOauth2ClientCondition extends AllNestedConditions {

	public IsReactiveOauth2ClientCondition() {
		super(ConfigurationPhase.PARSE_CONFIGURATION);
	}

	@ConditionalOnClass(OAuth2AuthorizedClientManager.class)
	static class IsSynchornizedOauth2Client {

	}

	@ConditionalOnWebApplication(type = Type.REACTIVE)
	static class IsServlet {

	}

}