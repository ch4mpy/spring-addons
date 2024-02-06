package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Conditional;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;

public class DefaultOAuth2AuthorizedClientManagerCondition extends AllNestedConditions {

    public DefaultOAuth2AuthorizedClientManagerCondition() {
        super(ConfigurationPhase.REGISTER_BEAN);
    }

    @Conditional(HasOAuth2RegistrationPropertiesCondition.class)
    static class HasOAuth2RegistrationCondition {}

    @ConditionalOnMissingBean(OAuth2AuthorizedClientManager.class)
    static class MissingOAuth2AuthorizedClientManagerCondition {}

}
