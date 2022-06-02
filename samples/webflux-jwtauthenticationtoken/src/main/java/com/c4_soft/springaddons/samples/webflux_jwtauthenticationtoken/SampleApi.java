package com.c4_soft.springaddons.samples.webflux_jwtauthenticationtoken;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import com.c4_soft.springaddons.security.oauth2.ReactiveJwt2AuthenticationConverter;
import com.c4_soft.springaddons.security.oauth2.config.JwtGrantedAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.reactive.AuthorizeExchangeSpecPostProcessor;

import reactor.core.publisher.Mono;

@SpringBootApplication
public class SampleApi {
	public static void main(String[] args) {
		new SpringApplicationBuilder(SampleApi.class).web(WebApplicationType.REACTIVE).run(args);
	}

	@EnableReactiveMethodSecurity()
	public static class WebSecurityConfig {

		@Bean
		public ReactiveJwt2AuthenticationConverter<JwtAuthenticationToken> authenticationConverter(JwtGrantedAuthoritiesConverter authoritiesConverter) {
			return jwt -> Mono.just(new JwtAuthenticationToken(jwt, authoritiesConverter.convert(jwt)));
		}

		@Bean
		public AuthorizeExchangeSpecPostProcessor authorizeExchangeSpecPostProcessor() {
			return (ServerHttpSecurity.AuthorizeExchangeSpec spec) -> spec
					.pathMatchers("/secured-route")
					.hasRole("AUTHORIZED_PERSONNEL")
					.anyExchange()
					.authenticated();
		}

	}
}
