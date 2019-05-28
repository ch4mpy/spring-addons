package com.c4soft.springaddons.showcase;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.jwt.Jwt;

import com.c4soft.springaddons.security.oauth2.server.resource.authentication.OAuth2Authentication;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.PrincipalGrantedAuthoritiesService;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.embedded.AuthoritiesClaimGrantedAuthoritiesService;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesJwtClaimSet;

@SpringBootApplication
public class JwtEmbeddedAuthoritiesApplication {
	public static void main(String[] args) {
		SpringApplication.run(JwtEmbeddedAuthoritiesApplication.class, args);
	}

	/*
	@EnableWebSecurity
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class SecurityConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/restricted/**").hasAuthority("AUTHORIZED_PERSONEL")
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.jwt()
						.jwtAuthenticationConverter(jwtAuthenticationConverter(jwtGrantedAuthoritiesConverter()));
			// @formatter:on
		}

		public static interface JwtAuthoritiesConverter extends Converter<Jwt, Collection<GrantedAuthority>> {}

		@Bean
		public JwtAuthoritiesConverter jwtGrantedAuthoritiesConverter() {
			return jwt -> new WithAuthoritiesJwtClaimSet(jwt.getClaims()).getAuthorities().stream()
					.map(SimpleGrantedAuthority::new)
					.collect(Collectors.toSet());
		}

		@Bean
		public JwtAuthenticationConverter jwtAuthenticationConverter(JwtAuthoritiesConverter jwtGrantedAuthoritiesConverter) {
			final JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
			converter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
			return converter;
		}
	}
	*/

	@EnableWebSecurity
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class AlternanteSecurityConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/restricted/**").hasAuthority("AUTHORIZED_PERSONEL")
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.jwt()
						.jwtAuthenticationConverter(jwtAuthenticationConverter(jwtAuthoritiesService()));
			// @formatter:on
		}

		public static interface JwtClaimsAuthenticationConverter extends Converter<Jwt, OAuth2Authentication<?>> {}

		@Bean
		public PrincipalGrantedAuthoritiesService jwtAuthoritiesService() {
			return new AuthoritiesClaimGrantedAuthoritiesService();
		}

		@Bean
		public JwtClaimsAuthenticationConverter jwtAuthenticationConverter(PrincipalGrantedAuthoritiesService jwtAuthoritiesService) {
			return jwt -> new OAuth2Authentication<>(
					new WithAuthoritiesJwtClaimSet(jwt.getClaims()),
					jwtAuthoritiesService);
		}
	}
}
