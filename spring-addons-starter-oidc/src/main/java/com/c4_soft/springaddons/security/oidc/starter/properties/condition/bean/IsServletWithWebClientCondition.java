package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.web.reactive.function.client.WebClient;

public class IsServletWithWebClientCondition extends AllNestedConditions {

    IsServletWithWebClientCondition() {
        super(ConfigurationPhase.REGISTER_BEAN);
    }

    @ConditionalOnWebApplication(type = Type.SERVLET)
    static class IsServlet {}

    @ConditionalOnClass(WebClient.class)
    static class IsWebClientOnClasspath {}

}
