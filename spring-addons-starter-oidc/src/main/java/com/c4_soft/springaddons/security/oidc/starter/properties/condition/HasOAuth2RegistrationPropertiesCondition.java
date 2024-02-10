package com.c4_soft.springaddons.security.oidc.starter.properties.condition;

public class HasOAuth2RegistrationPropertiesCondition extends HasPropertyPrefixCondition {

    public HasOAuth2RegistrationPropertiesCondition() {
        super("spring.security.oauth2.client.registration");
    }
}
