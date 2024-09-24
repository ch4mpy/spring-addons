package com.c4_soft.springaddons.security.oidc.starter.properties.condition;

public class HasTokenEdpointParametersPropertiesCondition extends HasPropertyPrefixCondition {

	public HasTokenEdpointParametersPropertiesCondition() {
		super("com.c4-soft.springaddons.oidc.client.token-request-params");
	}
}
