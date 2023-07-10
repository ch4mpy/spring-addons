package com.c4_soft.springaddons.security.oidc.starter.reactive;

import org.springframework.security.config.web.server.ServerHttpSecurity;

/**
 * Customize access-control for routes which where not listed in spring-addons "permit-all" properties for client and resource server filter chains
 *
 * @author ch4mp
 */
public interface AuthorizeExchangeSpecPostProcessor {
	ServerHttpSecurity.AuthorizeExchangeSpec authorizeHttpRequests(ServerHttpSecurity.AuthorizeExchangeSpec spec);
}