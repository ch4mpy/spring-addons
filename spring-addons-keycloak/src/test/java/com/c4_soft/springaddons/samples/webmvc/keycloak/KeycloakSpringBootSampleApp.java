package com.c4_soft.springaddons.samples.webmvc.keycloak;

import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.session.HttpSessionEventPublisher;

/**
 * Activate "keycloak" profile before running this app or you'll get errors at runtime due to missing keycloak properties
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@SpringBootApplication()
public class KeycloakSpringBootSampleApp {
	public static void main(String[] args) {
		SpringApplication.run(KeycloakSpringBootSampleApp.class, args);
	}

	@KeycloakConfiguration
	@Import(KeycloakSpringBootConfigResolver.class)
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class KeycloakConfig extends KeycloakWebSecurityConfigurerAdapter {
		@Autowired
		public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			auth.authenticationProvider(keycloakAuthenticationProvider());
		}

		@Bean
		@Override
		protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
			return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			super.configure(http);
			// @formatter:off
			http.authorizeRequests()
					.antMatchers("/secured-route").hasAuthority("AUTHORIZED_PERSONNEL")
					.anyRequest().authenticated();
			// @formatter:on
		}

		@Bean
		public ServletListenerRegistrationBean<HttpSessionEventPublisher> httpSessionEventPublisher() {
			return new ServletListenerRegistrationBean<>(new HttpSessionEventPublisher());
		}
	}
}
