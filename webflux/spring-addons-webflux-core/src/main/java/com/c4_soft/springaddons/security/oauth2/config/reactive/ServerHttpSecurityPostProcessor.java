package com.c4_soft.springaddons.security.oauth2.config.reactive;

import org.springframework.security.config.web.server.ServerHttpSecurity;

/**
 * Process {@link ServerHttpSecurity} of default security filter-chain  after it was processed by spring-addons.
 * This enables to override anything that was auto-configured (or add to it).
 * 
 * @author ch4mp
 *
 */
public interface ServerHttpSecurityPostProcessor {
    ServerHttpSecurity process(ServerHttpSecurity serverHttpSecurity);
}
