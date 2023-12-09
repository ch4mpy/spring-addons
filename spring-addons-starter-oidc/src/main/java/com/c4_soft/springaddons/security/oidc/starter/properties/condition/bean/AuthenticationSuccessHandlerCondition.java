package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.AnyNestedCondition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.NoneNestedConditions;
import org.springframework.context.annotation.Conditional;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;

public class AuthenticationSuccessHandlerCondition extends AllNestedConditions {

    public AuthenticationSuccessHandlerCondition() {
        super(ConfigurationPhase.REGISTER_BEAN);
    }

    @Conditional(NoAuthenticationSuccessHandlerCondition.class)
    static class AuthenticationSuccessHandlerMissingCondition {}

    @Conditional(PostLoginRedirectUriCondition.class)
    static class PostLoginRedirectUriProvidedCondition {}

    static class NoAuthenticationSuccessHandlerCondition extends NoneNestedConditions {

        public NoAuthenticationSuccessHandlerCondition() {
            super(ConfigurationPhase.REGISTER_BEAN);
        }

        @ConditionalOnBean(AuthenticationSuccessHandler.class)
        static class AuthenticationSuccessHandlerProvidedCondition {}

        @ConditionalOnBean(ServerAuthenticationSuccessHandler.class)
        static class ServerAuthenticationSuccessHandlerProvidedCondition {}
    }

    static class PostLoginRedirectUriCondition extends AnyNestedCondition {

        public PostLoginRedirectUriCondition() {
            super(ConfigurationPhase.REGISTER_BEAN);
        }

        @ConditionalOnProperty(name = "com.c4-soft.springaddons.oidc.client.post-login-redirect-host")
        static class PostLoginRedirectHostCondition {}

        @ConditionalOnProperty(name = "com.c4-soft.springaddons.oidc.client.post-login-redirect-path")
        static class PostLoginRedirectPathCondition {}
    }
}
