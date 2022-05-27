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
package com.c4_soft.springaddons.samples.webmvc.jwtauthenticationtoken;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;

import com.c4_soft.springaddons.samples.webmvc.jwtauthenticationtoken.service.JwtAuthenticationTokenMessageService;
import com.c4_soft.springaddons.samples.webmvc.jwtauthenticationtoken.web.GreetingController;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.ExpressionInterceptUrlRegistryPostProcessor;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.ServletSecurityBeans;

/**
 * Spring-boot application retrieving user ID from the JWT delivered by a Keycloak authorization-server and authorities defined from a
 * database
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@SpringBootApplication(scanBasePackageClasses = { JwtAuthenticationTokenMessageService.class, GreetingController.class })
public class JwtAuthenticationTokenServletAppWithJwtEmbeddedAuthorities {

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	@Import(ServletSecurityBeans.class)
	public static class WebSecurityConfig {

		@Bean
		public ExpressionInterceptUrlRegistryPostProcessor expressionInterceptUrlRegistryPostProcessor() {
			return (ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry registry) -> registry
					.antMatchers("/secured-route")
					.hasRole("AUTHORIZED_PERSONNEL")
					.anyRequest()
					.authenticated();
		}
	}

	public static void main(String[] args) {
		SpringApplication.run(JwtAuthenticationTokenServletAppWithJwtEmbeddedAuthorities.class, args);
	}
}
