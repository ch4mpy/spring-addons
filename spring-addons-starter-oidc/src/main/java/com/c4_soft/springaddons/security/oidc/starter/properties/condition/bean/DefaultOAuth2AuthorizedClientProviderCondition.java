package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Conditional;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;

public class DefaultOAuth2AuthorizedClientProviderCondition extends AllNestedConditions {

    public DefaultOAuth2AuthorizedClientProviderCondition() {
        super(ConfigurationPhase.REGISTER_BEAN);
    }

    @Conditional(HasOAuth2RegistrationPropertiesCondition.class)
    static class HasOAuth2RegistrationCondition {}

    @ConditionalOnMissingBean(OAuth2AuthorizedClientProvider.class)
    static class MissingOAuth2AuthorizedClientProviderCondition {}

}
