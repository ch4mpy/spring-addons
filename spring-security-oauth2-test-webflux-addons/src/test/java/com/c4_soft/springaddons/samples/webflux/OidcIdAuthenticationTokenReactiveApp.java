package com.c4_soft.springaddons.samples.webflux;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;

import com.c4_soft.springaddons.security.oauth2.config.reactive.AuthorizeExchangeSpecPostProcessor;

@SpringBootApplication
public class OidcIdAuthenticationTokenReactiveApp {

	@EnableReactiveMethodSecurity
	public static class WebSecurityConfig {
		@Bean
		public AuthorizeExchangeSpecPostProcessor authorizeExchangeSpecPostProcessor() {
			return spec -> spec.pathMatchers("/secured-endpoint").hasAnyRole("AUTHORIZED_PERSONNEL").anyExchange().authenticated();
		}
	}

	public static void main(String[] args) {
		SpringApplication.run(OidcIdAuthenticationTokenReactiveApp.class, args);
	}
}
