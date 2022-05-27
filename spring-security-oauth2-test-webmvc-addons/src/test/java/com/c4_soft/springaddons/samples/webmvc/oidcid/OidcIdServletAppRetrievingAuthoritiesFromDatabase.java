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
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;

import com.c4_soft.springaddons.samples.webmvc.oidcid.jpa.PersistedGrantedAuthoritiesRetriever;
import com.c4_soft.springaddons.samples.webmvc.oidcid.jpa.UserAuthority;
import com.c4_soft.springaddons.samples.webmvc.oidcid.jpa.UserAuthorityRepository;
import com.c4_soft.springaddons.samples.webmvc.oidcid.service.OidcIdMessageService;
import com.c4_soft.springaddons.samples.webmvc.oidcid.web.GreetingController;
import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2GrantedAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2OidcAuthenticationConverter;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.ExpressionInterceptUrlRegistryPostProcessor;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.ServletSecurityBeans;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcToken;

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

	@Configuration
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	@Import(ServletSecurityBeans.class)
	public static class WebSecurityConfig {

		@Autowired
		UserAuthorityRepository authoritiesRepo;

		@Bean
		public SynchronizedJwt2GrantedAuthoritiesConverter authoritiesConverter(UserAuthorityRepository authoritiesRepo) {
			return new PersistedGrantedAuthoritiesRetriever(authoritiesRepo);
		}

		@Bean
		public SynchronizedJwt2OidcAuthenticationConverter<OidcToken> authenticationConverter(UserAuthorityRepository authoritiesRepo) {
			return new SynchronizedJwt2OidcAuthenticationConverter<>(authoritiesConverter(authoritiesRepo), (var jwt) -> new OidcToken(jwt.getClaims()));
		}

		@Bean
		public ExpressionInterceptUrlRegistryPostProcessor expressionInterceptUrlRegistryPostProcessor() {
			return (ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry registry) -> registry
					.antMatchers("/secured-route")
					.hasRole("AUTHORIZED_PERSONNEL")
					.anyRequest()
					.authenticated();
		}
	}

	@Configuration(proxyBeanMethods = false)
	@EntityScan(basePackageClasses = UserAuthority.class)
	public static class PersistenceConfig {
	}
}
