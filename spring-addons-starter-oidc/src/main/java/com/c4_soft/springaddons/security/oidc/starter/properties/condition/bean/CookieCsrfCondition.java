package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.boot.autoconfigure.condition.AnyNestedCondition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

public class CookieCsrfCondition extends AnyNestedCondition {

	public CookieCsrfCondition() {
		super(ConfigurationPhase.REGISTER_BEAN);
	}

	@ConditionalOnProperty(name = "com.c4-soft.springaddons.oidc.client.csrf", havingValue = "cookie-accessible-from-js")
	static class ClientCookieAccessibleFromJsCondition {
	}

	@ConditionalOnProperty(name = "com.c4-soft.springaddons.oidc.client.csrf", havingValue = "cookie-http-only")
	static class clientHttpOnlyCookieCondition {
	}

	@ConditionalOnProperty(name = "com.c4-soft.springaddons.oidc.resourceserver.csrf", havingValue = "cookie-http-only")
	static class ResourceServerHttpOnlyCookieCondition {
	}

	@ConditionalOnProperty(name = "com.c4-soft.springaddons.oidc.resourceserver.csrf", havingValue = "cookie-accessible-from-js")
	static class ResourceServerCookieAccessibleFromJsCondition {
	}

}