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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class ShowcaseApplication {
	public static void main(String[] args) {
		SpringApplication.run(ShowcaseApplication.class, args);
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
					.antMatchers("/restricted/**").hasAuthority("AUTHORIZED_PERSONEL")
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.jwt();
			// @formatter:on
		}

		/**
		 * chains the two preceding converters
		 * @return scopes as granted-authorities
		 */
		@Bean
		public Converter<Jwt, Collection<GrantedAuthority>> jwtAuthoritiesConverter() {
			return jwt -> Stream.of(Optional.of(jwt.getClaimAsString("scope")).orElse("").split(" "))
					.map(s -> new SimpleGrantedAuthority(AUTHORITIES_PREFIX + s))
					.collect(Collectors.toSet());
		}

		@Bean
		public JwtAuthenticationConverter authenticationConverter(Converter<Jwt, Collection<GrantedAuthority>> jwtAuthoritiesConverter) {
			final var authenticationConverter = new JwtAuthenticationConverter();
			authenticationConverter.setJwtGrantedAuthoritiesConverter(jwtAuthoritiesConverter);
			return authenticationConverter;
		}
	}

	@RestController
	@RequestMapping("/")
	public static class ShowcaseController {
		@GetMapping("greeting")
		public String getGreeting(Authentication authentication) {
			return String.format("Hello, %s!", authentication.getName());
		}

		@GetMapping("restricted/greeting")
		public String getRestrictedGreeting(Authentication authentication) {
			return "Welcome to restricted area.";
		}

		@GetMapping("jwt")
		public String getJwtClaims(@AuthenticationPrincipal Jwt jwt) {
			return jwt.getClaims().toString();
		}
	}
}
