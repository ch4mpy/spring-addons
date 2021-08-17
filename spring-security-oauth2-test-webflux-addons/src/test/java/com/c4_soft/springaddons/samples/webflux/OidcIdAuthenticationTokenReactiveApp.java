package com.c4_soft.springaddons.samples.webflux;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.web.server.SecurityWebFilterChain;

import com.c4_soft.springaddons.security.oauth2.ReactiveJwt2GrantedAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.oidc.ReactiveJwt2OidcIdAuthenticationConverter;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;

import reactor.core.publisher.Flux;

@SpringBootApplication(scanBasePackageClasses = OidcIdAuthenticationTokenReactiveApp.class)
public class OidcIdAuthenticationTokenReactiveApp {

	@Configuration
	public static class JwtConfig {

		@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
		String issuerUri;

		@Bean
		public ReactiveJwtDecoder jwtDecoder() {
			return ReactiveJwtDecoders.fromOidcIssuerLocation(issuerUri);
		}
	}

	@EnableWebFluxSecurity
	@EnableReactiveMethodSecurity
	public static class ReactiveJwtSecurityConfig {

		@Bean
		public ReactiveJwt2GrantedAuthoritiesConverter authoritiesConverter() {
			return (var jwt) -> {
				final var roles =
						Optional
								.ofNullable((JSONObject) jwt.getClaims().get("realm_access"))
								.flatMap(realmAccess -> Optional.ofNullable((JSONArray) realmAccess.get("roles")))
								.orElse(new JSONArray());
				return Flux.fromStream(roles.stream().map(Object::toString).map(role -> new SimpleGrantedAuthority("ROLE_" + role)));
			};
		}

		@Bean
		public ReactiveJwt2OidcIdAuthenticationConverter authenticationConverter(ReactiveJwt2GrantedAuthoritiesConverter authoritiesConverter) {
			return new ReactiveJwt2OidcIdAuthenticationConverter(authoritiesConverter);
		}

		@Bean
		public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http, ReactiveJwt2OidcIdAuthenticationConverter authenticationConverter) {
			// @formatter:off
			http.csrf().disable().httpBasic().disable().formLogin().disable();
			http.authorizeExchange().pathMatchers("/secured-endpoint").hasAnyRole("AUTHORIZED_PERSONNEL").anyExchange()
					.authenticated();
			http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(authenticationConverter);
			// @formatter:on

			return http.build();
		}
	}

	public static void main(String[] args) {
		SpringApplication.run(OidcIdAuthenticationTokenReactiveApp.class, args);
	}
}
