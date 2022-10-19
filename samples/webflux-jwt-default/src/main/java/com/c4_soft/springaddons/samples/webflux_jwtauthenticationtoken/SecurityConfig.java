package com.c4_soft.springaddons.samples.webflux_jwtauthenticationtoken;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;

import com.c4_soft.springaddons.security.oauth2.config.reactive.AuthorizeExchangeSpecPostProcessor;

@EnableReactiveMethodSecurity()
@Configuration
public class SecurityConfig {

    @Bean
    public AuthorizeExchangeSpecPostProcessor authorizeExchangeSpecPostProcessor() {
        // @formatter:off
		return (ServerHttpSecurity.AuthorizeExchangeSpec spec) -> spec
				.pathMatchers("/secured-route").hasRole("AUTHORIZED_PERSONNEL")
				.anyExchange().authenticated();
		// @formatter:on
    }

}