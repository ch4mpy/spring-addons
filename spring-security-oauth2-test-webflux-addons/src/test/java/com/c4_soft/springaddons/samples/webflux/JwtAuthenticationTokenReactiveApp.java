package com.c4_soft.springaddons.samples.webflux;

import java.util.Collection;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.SecurityWebFilterChain;

import com.c4_soft.springaddons.samples.webflux.domain.MessageService;
import com.c4_soft.springaddons.samples.webflux.web.GreetingController;
import com.c4_soft.springaddons.security.oauth2.keycloak.KeycloakEmbeddedAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.keycloak.KeycloakJwtAuthenticationTokenConverter;

import reactor.core.publisher.Mono;

@SpringBootApplication(
		scanBasePackageClasses = {
				JwtAuthenticationTokenReactiveApp.ReactiveJwtSecurityConfig.class,
				GreetingController.class,
				MessageService.class })
public class JwtAuthenticationTokenReactiveApp {

	public static void main(String[] args) {
		SpringApplication.run(JwtAuthenticationTokenReactiveApp.class, args);
	}

	@EnableWebFluxSecurity
	@EnableReactiveMethodSecurity
	public static class ReactiveJwtSecurityConfig {

		@Bean
		public SecurityWebFilterChain springSecurityFilterChain(
				ServerHttpSecurity http,
				Converter<Jwt, Mono<JwtAuthenticationToken>> authenticationConverter) {
			// @formatter:off
			http.csrf().disable().httpBasic().disable().formLogin().disable();
			http.authorizeExchange()
					.pathMatchers("/secured-endpoint").hasAnyRole("AUTHORIZED_PERSONNEL")
					.anyExchange().authenticated();
			http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(authenticationConverter);
			// @formatter:on
			return http.build();
		}

		@Bean
		public Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter() {
			return new KeycloakEmbeddedAuthoritiesConverter();
		}

		@Bean
		public JwtAuthenticationConverter
				authenticationConverter(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
			return jwt -> Mono.just(jwt)
					.map(new KeycloakJwtAuthenticationTokenConverter(authoritiesConverter)::convert);
		}

	}

	@Configuration
	public static class ReactiveJwtDecoderConfig {

		@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
		String issuerUri;

		@Bean
		public ReactiveJwtDecoder jwtDecoder() {
			return ReactiveJwtDecoders.fromOidcIssuerLocation(issuerUri);
		}
	}

	public static interface JwtAuthenticationConverter extends Converter<Jwt, Mono<JwtAuthenticationToken>> {
	}

}
