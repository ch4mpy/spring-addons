package com.c4_soft.springaddons.security.oauth2.config.reactive;

import org.springframework.security.config.web.server.ServerHttpSecurity;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;

/**
 * Customize access-control for routes which where not listed in {@link SpringAddonsSecurityProperties#permitAll}
 * 
 * @author ch4mp
 *
 */
public interface ResourceServerAuthorizeExchangeSpecPostProcessor {
	ServerHttpSecurity.AuthorizeExchangeSpec authorizeHttpRequests(ServerHttpSecurity.AuthorizeExchangeSpec spec);
}