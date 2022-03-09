package com.c4_soft.springaddons.samples.webflux;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity.AuthorizeExchangeSpec;
import org.springframework.web.server.ServerWebExchange;

import com.c4_soft.springaddons.security.oauth2.config.OidcReactiveApiSecurityConfig;
import com.c4_soft.springaddons.security.oauth2.config.ReactiveSecurityBeans;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;

@SpringBootApplication(scanBasePackageClasses = OidcIdAuthenticationTokenReactiveApp.class)
public class OidcIdAuthenticationTokenReactiveApp {

	@EnableWebFluxSecurity
	@EnableReactiveMethodSecurity
	@Import({ SpringAddonsSecurityProperties.class, ReactiveSecurityBeans.class })
	public static class WebSecurityConfig extends OidcReactiveApiSecurityConfig {
		public WebSecurityConfig(
				ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver,
				SpringAddonsSecurityProperties securityProperties,
				ServerProperties serverProperties) {
			super(authenticationManagerResolver, securityProperties, serverProperties);
		}

		@Override
		protected AuthorizeExchangeSpec authorizeRequests(AuthorizeExchangeSpec spec) {
			// @formatter:off
			return spec
					.pathMatchers("/secured-endpoint").hasAnyRole("AUTHORIZED_PERSONNEL")
					.anyExchange().authenticated();
			// @formatter:on
		}
	}

	public static void main(String[] args) {
		SpringApplication.run(OidcIdAuthenticationTokenReactiveApp.class, args);
	}
}
