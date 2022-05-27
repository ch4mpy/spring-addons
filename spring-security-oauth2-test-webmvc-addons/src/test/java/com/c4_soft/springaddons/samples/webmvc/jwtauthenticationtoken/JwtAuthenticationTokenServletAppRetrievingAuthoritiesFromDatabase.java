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

import java.util.Collection;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import com.c4_soft.springaddons.samples.webmvc.jwtauthenticationtoken.jpa.PersistedGrantedAuthoritiesRetriever;
import com.c4_soft.springaddons.samples.webmvc.jwtauthenticationtoken.jpa.UserAuthority;
import com.c4_soft.springaddons.samples.webmvc.jwtauthenticationtoken.jpa.UserAuthorityRepository;
import com.c4_soft.springaddons.samples.webmvc.jwtauthenticationtoken.service.JwtAuthenticationTokenMessageService;
import com.c4_soft.springaddons.samples.webmvc.jwtauthenticationtoken.web.GreetingController;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.ExpressionInterceptUrlRegistryPostProcessor;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.ServletSecurityBeans;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@SpringBootApplication(scanBasePackageClasses = { JwtAuthenticationTokenMessageService.class, GreetingController.class })
public class JwtAuthenticationTokenServletAppRetrievingAuthoritiesFromDatabase {
	public static void main(String[] args) {
		SpringApplication.run(JwtAuthenticationTokenServletAppRetrievingAuthoritiesFromDatabase.class, args);
	}

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

		@Bean
		public Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter(UserAuthorityRepository authoritiesRepo) {
			return new PersistedGrantedAuthoritiesRetriever(authoritiesRepo);
		}

		@Bean
		public Converter<Jwt, JwtAuthenticationToken> authenticationConverter(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
			return (Jwt jwt) -> new JwtAuthenticationToken(jwt, authoritiesConverter.convert(jwt));
		}
	}

	@Configuration(proxyBeanMethods = false)
	@EntityScan(basePackageClasses = UserAuthority.class)
	public static class PersistenceConfig {
	}
}
