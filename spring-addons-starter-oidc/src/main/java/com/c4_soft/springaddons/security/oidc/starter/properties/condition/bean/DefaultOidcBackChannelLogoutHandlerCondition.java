package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OidcBackChannelLogoutHandler;
import org.springframework.security.config.web.server.OidcBackChannelServerLogoutHandler;

public class DefaultOidcBackChannelLogoutHandlerCondition extends AllNestedConditions {

	public DefaultOidcBackChannelLogoutHandlerCondition() {
		super(ConfigurationPhase.REGISTER_BEAN);
	}

	@ConditionalOnProperty(name = "com.c4-soft.springaddons.oidc.client.back-channel-logout.enabled")
	static class BackChannelLogoutEnabledCondition {
	}
	
	@ConditionalOnProperty(name = "com.c4-soft.springaddons.oidc.client.back-channel-logout.handler-bean-name", havingValue = "", matchIfMissing = true)
    static class BackChannelLogoutHandlerBeanNameEmptyCondition {
    }

	@ConditionalOnMissingBean(OidcBackChannelLogoutHandler.class)
	static class NoOidcBackChannelLogoutHandlerCondition {
	}

	@ConditionalOnMissingBean(OidcBackChannelServerLogoutHandler.class)
	static class NoOidcBackChannelServerLogoutHandlerCondition {
	}

}
