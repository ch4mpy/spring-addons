package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.oauth2.client.oidc.server.session.ReactiveOidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionRegistry;

public class DefaultOidcSessionRegistryCondition extends AllNestedConditions {

    public DefaultOidcSessionRegistryCondition() {
        super(ConfigurationPhase.REGISTER_BEAN);
    }

    @ConditionalOnProperty(name = "com.c4-soft.springaddons.oidc.client.back-channel-logout.enabled")
    static class BackChannelLogoutEnabledCondition {}

    @ConditionalOnMissingBean(OidcSessionRegistry.class)
    static class NoOidcSessionRegistryCondition {}

    @ConditionalOnMissingBean(ReactiveOidcSessionRegistry.class)
    static class NoReactiveOidcSessionRegistryCondition {}

}
