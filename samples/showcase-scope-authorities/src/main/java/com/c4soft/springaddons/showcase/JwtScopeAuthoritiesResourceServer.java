package com.c4soft.springaddons.showcase;

import java.util.Collection;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

@SpringBootApplication
public class JwtScopeAuthoritiesResourceServer {
	public static void main(String[] args) {
		SpringApplication.run(JwtScopeAuthoritiesResourceServer.class, args);
	}

	@EnableWebSecurity
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class SecurityConfig extends WebSecurityConfigurerAdapter {
		private static final String AUTHORITIES_PREFIX = "SCOPE_";

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/restricted/**").hasAuthority("SCOPE_showcase:AUTHORIZED_PERSONEL")
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.jwt();
			// @formatter:on
		}

		@Bean
		public Converter<Jwt, Collection<GrantedAuthority>> jwtAuthoritiesConverter() {
			return new JwtScopeAuthoritiesConverter();
		}

		@Bean
		public JwtAuthenticationConverter authenticationConverter(Converter<Jwt, Collection<GrantedAuthority>> jwtAuthoritiesConverter) {
			final var authenticationConverter = new JwtAuthenticationConverter();
			authenticationConverter.setJwtGrantedAuthoritiesConverter(jwtAuthoritiesConverter);
			return authenticationConverter;
		}

		private static final class JwtScopeAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
			@Override
			public Collection<GrantedAuthority> convert(Jwt source) {
				return Stream.of(Optional.of(source.getClaimAsString("scope")).orElse("").split(" "))
						.map(s -> new SimpleGrantedAuthority(AUTHORITIES_PREFIX + s))
						.collect(Collectors.toSet());
			}
		}
	}
}
