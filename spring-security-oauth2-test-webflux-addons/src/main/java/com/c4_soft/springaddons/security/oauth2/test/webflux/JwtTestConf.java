package com.c4_soft.springaddons.security.oauth2.test.webflux;

import static org.mockito.Mockito.mock;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

@TestConfiguration(proxyBeanMethods = false)
@Order(Ordered.LOWEST_PRECEDENCE)
public class JwtTestConf {
	@Bean
	public ReactiveJwtDecoder jwtDecoder() {
		return mock(ReactiveJwtDecoder.class);
	}
}