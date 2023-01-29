package com.c4_soft.springaddons.security.oauth2.config.reactive;

import org.springframework.security.config.web.server.ServerHttpSecurity;

public interface AuthorizeExchangeSpecPostProcessor {
	ServerHttpSecurity.AuthorizeExchangeSpec authorizeHttpRequests(ServerHttpSecurity.AuthorizeExchangeSpec spec);
}