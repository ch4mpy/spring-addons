package com.c4_soft.springaddons.security.oidc.starter.properties.condition;

public class HasRestConfiguration extends HasPropertyPrefixCondition {

    public HasRestConfiguration() {
        super("com.c4-soft.springaddons.oidc.client.rest");
    }
}
