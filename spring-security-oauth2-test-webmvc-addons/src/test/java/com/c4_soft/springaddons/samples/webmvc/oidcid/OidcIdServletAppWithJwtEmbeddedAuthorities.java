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

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;

import com.c4_soft.springaddons.samples.webmvc.oidcid.service.OidcIdMessageService;
import com.c4_soft.springaddons.samples.webmvc.oidcid.web.GreetingController;
import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2GrantedAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.AbstractOidcServletApiSecurityConfig;
import com.c4_soft.springaddons.security.oauth2.config.KeycloakJwt2GrantedAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.SecurityProperties;

/**
 * Spring-boot application using authorities embedded in the JWT by a Keycloak authorization-server (authorities must be defined and mapped
 * to users in Keycloak admin console)
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@SpringBootApplication(scanBasePackageClasses = { OidcIdMessageService.class, GreetingController.class })
public class OidcIdServletAppWithJwtEmbeddedAuthorities {

	@EnableWebSecurity
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	@Import(SecurityProperties.class)
	public static class WebSecurityConfig extends AbstractOidcServletApiSecurityConfig {

		public WebSecurityConfig(@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri, SecurityProperties securityProperties) {
			super(issuerUri, securityProperties);
		}

		@Override
		public SynchronizedJwt2GrantedAuthoritiesConverter authoritiesConverter() {
			return new KeycloakJwt2GrantedAuthoritiesConverter(getSecurityProperties());
		}

		@Override
		protected ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry authorizeRequests(
				ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry registry) {
			return registry.antMatchers("/secured-route").hasRole("AUTHORIZED_PERSONNEL").anyRequest().authenticated();
		}
	}

	public static void main(String[] args) {
		SpringApplication.run(OidcIdServletAppWithJwtEmbeddedAuthorities.class, args);
	}
}
