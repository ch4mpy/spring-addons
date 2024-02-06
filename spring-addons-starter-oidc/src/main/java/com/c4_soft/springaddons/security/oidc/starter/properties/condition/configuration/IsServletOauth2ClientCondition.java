package com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;

public class IsServletOauth2ClientCondition extends AllNestedConditions {

    public IsServletOauth2ClientCondition() {
        super(ConfigurationPhase.PARSE_CONFIGURATION);
    }

    @ConditionalOnClass(OAuth2AuthorizedClientManager.class)
    static class IsSynchornizedOauth2Client {

    }

    @ConditionalOnWebApplication(type = Type.SERVLET)
    static class IsServlet {

    }

}
