package com.c4_soft.springaddons.samples.webflux;

import java.util.Collection;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.web.server.SecurityWebFilterChain;

import com.c4_soft.springaddons.security.oauth2.keycloak.KeycloackOidcIdAuthenticationConverter;
import com.c4_soft.springaddons.security.oauth2.keycloak.KeycloackEmbeddedAuthoritiesConverter;

import reactor.core.publisher.Mono;

@SpringBootApplication(scanBasePackageClasses = OidcIdAuthenticationTokenReactiveApp.class)
public class OidcIdAuthenticationTokenReactiveApp {
	public static void main(String[] args) {
		SpringApplication.run(OidcIdAuthenticationTokenReactiveApp.class, args);
	}

	@EnableWebFluxSecurity
	@EnableReactiveMethodSecurity
	public static class ReactiveJwtSecurityConfig {

		@Bean
		public SecurityWebFilterChain
				springSecurityFilterChain(ServerHttpSecurity http, AuthenticationConverter authenticationConverter) {
			// @formatter:off
			http.csrf().disable().httpBasic().disable().formLogin().disable();
			http.authorizeExchange().pathMatchers("/secured-endpoint").hasAnyRole("AUTHORIZED_PERSONNEL").anyExchange()
					.authenticated();
			http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(authenticationConverter);
			// @formatter:on

			return http.build();
		}

		@Bean
		public Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter() {
			return new KeycloackEmbeddedAuthoritiesConverter();
		}

		@Bean
		public AuthenticationConverter
				authenticationConverter(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
			KeycloackOidcIdAuthenticationConverter extractor =
					new KeycloackOidcIdAuthenticationConverter(authoritiesConverter);
			return jwt -> Mono.just(jwt).map(extractor::convert);
		}
	}

	@Configuration
	public static class JwtConfig {

		@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
		String issuerUri;

		@Bean
		public ReactiveJwtDecoder jwtDecoder() {
			return ReactiveJwtDecoders.fromOidcIssuerLocation(issuerUri);
		}
	}

	static interface AuthenticationConverter extends Converter<Jwt, Mono<AbstractAuthenticationToken>> {
	}
}
