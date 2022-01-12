/*
 * Copyright 2020 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may
 * obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */
package com.c4_soft.springaddons.samples.webmvc.oidcid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;

import com.c4_soft.springaddons.samples.webmvc.oidcid.jpa.PersistedGrantedAuthoritiesRetriever;
import com.c4_soft.springaddons.samples.webmvc.oidcid.jpa.UserAuthority;
import com.c4_soft.springaddons.samples.webmvc.oidcid.jpa.UserAuthorityRepository;
import com.c4_soft.springaddons.samples.webmvc.oidcid.service.OidcIdMessageService;
import com.c4_soft.springaddons.samples.webmvc.oidcid.web.GreetingController;
import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2GrantedAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcToken;
import com.c4_soft.springaddons.security.oauth2.oidc.SynchronizedJwt2OidcAuthenticationConverter;

/**
 * Spring-boot application retrieving user ID from the JWT delivered by a Keycloak authorization-server and authorities defined from a
 * database
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@SpringBootApplication(scanBasePackageClasses = { OidcIdMessageService.class, GreetingController.class })
public class OidcIdServletAppRetrievingAuthoritiesFromDatabase {
	public static void main(String[] args) {
		SpringApplication.run(OidcIdServletAppRetrievingAuthoritiesFromDatabase.class, args);
	}

	@EnableWebSecurity
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class WebSecurityConfig extends WebSecurityConfigurerAdapter {

		@Autowired
		UserAuthorityRepository authoritiesRepo;

		public SynchronizedJwt2GrantedAuthoritiesConverter authoritiesConverter(UserAuthorityRepository authoritiesRepo) {
			return new PersistedGrantedAuthoritiesRetriever(authoritiesRepo);
		}

		public SynchronizedJwt2OidcAuthenticationConverter<OidcToken> authenticationConverter(UserAuthorityRepository authoritiesRepo) {
			return new SynchronizedJwt2OidcAuthenticationConverter<>(authoritiesConverter(authoritiesRepo), (Jwt jwt) -> new OidcToken(jwt.getClaims()));
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http.csrf().disable().httpBasic().disable().formLogin().disable();
			http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(authenticationConverter(authoritiesRepo));
			http.authorizeRequests().antMatchers("/secured-route").hasRole("AUTHORIZED_PERSONNEL").anyRequest()
					.authenticated();
			// @formatter:on
		}
	}

	@Configuration(proxyBeanMethods = false)
	public static class JwtConfig {
		@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
		String issuerUri;

		@Bean
		public JwtDecoder jwtDecoder() {
			return JwtDecoders.fromOidcIssuerLocation(issuerUri);
		}
	}

	@Configuration(proxyBeanMethods = false)
	@EntityScan(basePackageClasses = UserAuthority.class)
	public static class PersistenceConfig {
	}
}
