package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Conditional;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

import com.c4_soft.springaddons.security.oidc.starter.properties.condition.HasAuthorizationCodeRegistrationPropertiesCondition;

public class DefaultOAuth2AuthorizedClientRepositoryCondition extends AllNestedConditions {

    public DefaultOAuth2AuthorizedClientRepositoryCondition() {
        super(ConfigurationPhase.REGISTER_BEAN);
    }

    @Conditional(HasAuthorizationCodeRegistrationPropertiesCondition.class)
    static class HasAuthorizationCodeRegistrationCondition {}

    @ConditionalOnMissingBean(OAuth2AuthorizedClientRepository.class)
    static class MissingOAuth2AuthorizedClientRepositoryCondition {}

}
