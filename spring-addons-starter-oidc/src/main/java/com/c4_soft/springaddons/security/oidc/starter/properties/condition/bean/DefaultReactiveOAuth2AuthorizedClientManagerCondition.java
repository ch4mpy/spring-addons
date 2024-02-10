package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Conditional;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;

import com.c4_soft.springaddons.security.oidc.starter.properties.condition.HasOAuth2RegistrationPropertiesCondition;

public class DefaultReactiveOAuth2AuthorizedClientManagerCondition extends AllNestedConditions {

    public DefaultReactiveOAuth2AuthorizedClientManagerCondition() {
        super(ConfigurationPhase.REGISTER_BEAN);
    }

    @Conditional(HasOAuth2RegistrationPropertiesCondition.class)
    static class HasOAuth2RegistrationCondition {}

    @ConditionalOnMissingBean(ReactiveOAuth2AuthorizedClientManager.class)
    static class MissingReactiveOAuth2AuthorizedClientManagerCondition {}

}
