package com.c4_soft.springaddons.security.oidc.starter.properties.condition;

public class HasCorsPropertiesCondition extends HasPropertyPrefixCondition {

    public HasCorsPropertiesCondition() {
        super("com.c4-soft.springaddons.oidc.cors");
    }
}
