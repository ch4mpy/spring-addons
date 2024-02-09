package com.c4_soft.springaddons.security.oidc.starter.reactive;

import org.springframework.security.config.web.server.ServerHttpSecurity;

/**
 * Process {@link ServerHttpSecurity} of default security filter-chain after it was processed by spring-addons. This enables to override anything that was
 * auto-configured (or add to it).
 * 
 * @author ch4mp
 */
public interface ReactiveHttpSecurityPostProcessor {
	ServerHttpSecurity process(ServerHttpSecurity serverHttpSecurity);
}
