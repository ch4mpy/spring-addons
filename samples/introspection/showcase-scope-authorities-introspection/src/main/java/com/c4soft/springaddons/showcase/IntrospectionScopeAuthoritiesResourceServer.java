package com.c4soft.springaddons.showcase;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@SpringBootApplication
@ComponentScan("com.c4soft.springaddons.samples.common")
public class IntrospectionScopeAuthoritiesResourceServer {
	public static void main(String[] args) {
		SpringApplication.run(IntrospectionScopeAuthoritiesResourceServer.class, args);
	}

	@EnableWebSecurity
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class SecurityConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/restricted/**").hasAuthority("SCOPE_showcase:AUTHORIZED_PERSONEL")
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.opaqueToken()
						.introspectionUri("https://localhost:9080/introspect")
						.introspectionClientCredentials("introspection", "password");
			// @formatter:on
		}
	}

}
