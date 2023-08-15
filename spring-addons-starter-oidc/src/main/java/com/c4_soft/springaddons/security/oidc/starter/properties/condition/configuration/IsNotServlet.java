package com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration;

import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.autoconfigure.condition.NoneNestedConditions;

public class IsNotServlet extends NoneNestedConditions {

	public IsNotServlet() {
		super(ConfigurationPhase.PARSE_CONFIGURATION);
	}

	@ConditionalOnWebApplication(type = Type.SERVLET)
	static class IsServletWebApp {

	}

}