package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.AnyNestedCondition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.NoneNestedConditions;
import org.springframework.context.annotation.Conditional;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;

public class DefaultAuthenticationFailureHandlerCondition extends AllNestedConditions {

    public DefaultAuthenticationFailureHandlerCondition() {
        super(ConfigurationPhase.REGISTER_BEAN);
    }

    @Conditional(NoAuthenticationFailureHandlerCondition.class)
    static class AuthenticationFailureHandlerMissingCondition {}

    @Conditional(PostLoginRedirectUriCondition.class)
    static class PostLoginRedirectUriProvidedCondition {}

    static class NoAuthenticationFailureHandlerCondition extends NoneNestedConditions {

        public NoAuthenticationFailureHandlerCondition() {
            super(ConfigurationPhase.REGISTER_BEAN);
        }

        @ConditionalOnBean(AuthenticationFailureHandler.class)
        static class AuthenticationFailureHandlerProvidedCondition {}

        @ConditionalOnBean(ServerAuthenticationFailureHandler.class)
        static class ServerAuthenticationFailureHandlerProvidedCondition {}
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
