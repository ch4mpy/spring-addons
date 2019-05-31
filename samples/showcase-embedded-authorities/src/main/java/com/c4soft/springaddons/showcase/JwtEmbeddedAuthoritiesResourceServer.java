package com.c4soft.springaddons.showcase;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.jwt.Jwt;

import com.c4soft.springaddons.security.oauth2.server.resource.authentication.OAuth2ClaimSetAuthentication;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.PrincipalGrantedAuthoritiesService;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.embedded.ClaimGrantedAuthoritiesService;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesJwtClaimSet;

@SpringBootApplication
public class JwtEmbeddedAuthoritiesResourceServer {
	public static void main(String[] args) {
		SpringApplication.run(JwtEmbeddedAuthoritiesResourceServer.class, args);
	}

	@EnableWebSecurity
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class AlternanteSecurityConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/restricted/**").hasAuthority("showcase:AUTHORIZED_PERSONEL")
					.anyRequest().permitAll()
					.and()
				.oauth2ResourceServer()
					.jwt()
						.jwtAuthenticationConverter(jwtAuthenticationConverter(jwtAuthoritiesService()));
			// @formatter:on
		}

		public static interface JwtClaimsAuthenticationConverter extends Converter<Jwt, OAuth2ClaimSetAuthentication<?>> {}

		public PrincipalGrantedAuthoritiesService jwtAuthoritiesService() {
			return new ClaimGrantedAuthoritiesService();
		}

		public JwtClaimsAuthenticationConverter jwtAuthenticationConverter(PrincipalGrantedAuthoritiesService jwtAuthoritiesService) {
			return jwt -> new OAuth2ClaimSetAuthentication<>(
					new WithAuthoritiesJwtClaimSet(jwt.getClaims()),
					jwtAuthoritiesService);
		}
	}
}
