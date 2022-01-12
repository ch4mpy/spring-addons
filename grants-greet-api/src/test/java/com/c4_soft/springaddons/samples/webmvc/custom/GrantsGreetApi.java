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
package com.c4_soft.springaddons.samples.webmvc.custom;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.Jwt;

import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2AuthenticationConverter;
import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2OidcTokenConverter;
import com.c4_soft.springaddons.security.oauth2.config.OidcServletApiSecurityConfig;
import com.c4_soft.springaddons.security.oauth2.config.ServletSecurityBeans;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcToken;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@SpringBootApplication
@Import({ SpringAddonsSecurityProperties.class })
public class GrantsGreetApi {

	@Configuration
	static class ServletSecurityBeansOverrides extends ServletSecurityBeans {
		ServletSecurityBeansOverrides(
				@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri,
				SpringAddonsSecurityProperties securityProperties) {
			super(issuerUri, securityProperties);
		}

		// token converter override
		@Override
		@Bean
		public SynchronizedJwt2OidcTokenConverter<OidcToken> tokenConverter() {
			return (Jwt jwt) -> new CustomOidcToken(jwt.getClaims());
		}
	}

	@EnableWebSecurity
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class WebSecurityConfig extends OidcServletApiSecurityConfig {
		public WebSecurityConfig(
				SynchronizedJwt2AuthenticationConverter<? extends AbstractAuthenticationToken> authenticationConverter,
				SpringAddonsSecurityProperties securityProperties) {
			super(authenticationConverter, securityProperties);
		}
	}

	public static void main(String[] args) {
		SpringApplication.run(GrantsGreetApi.class, args);
	}
}
