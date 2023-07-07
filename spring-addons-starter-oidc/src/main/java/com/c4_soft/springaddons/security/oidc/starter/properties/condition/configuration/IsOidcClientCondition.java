package com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration;

import org.springframework.boot.autoconfigure.condition.AnyNestedCondition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

public class IsOidcClientCondition extends AnyNestedCondition {

	public IsOidcClientCondition() {
		super(ConfigurationPhase.PARSE_CONFIGURATION);
	}

	@ConditionalOnExpression("!(T(org.springframework.util.StringUtils).isEmpty('${com.c4-soft.springaddons.oidc.client.security-matchers:}') && T(org.springframework.util.StringUtils).isEmpty('${com.c4-soft.springaddons.oidc.client.security-matchers[0]:}'))")
	static class Value1Condition {

	}

	@ConditionalOnProperty(name = "com.c4-soft.springaddons.oidc.client.security-matchers[0]")
	static class Value2Condition {

	}

}