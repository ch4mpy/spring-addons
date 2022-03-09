package com.c4_soft.springaddons.security.oauth2.test.webflux;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.web.server.ServerWebExchange;

@TestConfiguration(proxyBeanMethods = false)
@Order(Ordered.LOWEST_PRECEDENCE)
public class JwtTestConf {
	@Bean
	public ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver() {
		return (var context) -> null;
	}
}