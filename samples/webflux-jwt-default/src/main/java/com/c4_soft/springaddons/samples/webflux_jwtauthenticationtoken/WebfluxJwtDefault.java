package com.c4_soft.springaddons.samples.webflux_jwtauthenticationtoken;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;

import com.c4_soft.springaddons.security.oauth2.config.reactive.AuthorizeExchangeSpecPostProcessor;

@SpringBootApplication
public class WebfluxJwtDefault {
	public static void main(String[] args) {
		new SpringApplicationBuilder(WebfluxJwtDefault.class).web(WebApplicationType.REACTIVE).run(args);
	}

	@EnableReactiveMethodSecurity()
	public static class SecurityConfig {

		@Bean
		public AuthorizeExchangeSpecPostProcessor authorizeExchangeSpecPostProcessor() {
			// @formatter:off
			return (ServerHttpSecurity.AuthorizeExchangeSpec spec) -> spec
					.pathMatchers("/secured-route").hasRole("AUTHORIZED_PERSONNEL")
					.anyExchange().authenticated();
			// @formatter:on
		}

	}
}
