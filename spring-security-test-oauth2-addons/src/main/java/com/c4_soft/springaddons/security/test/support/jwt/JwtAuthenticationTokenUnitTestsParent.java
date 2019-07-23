/*
 * Copyright 2019 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.c4_soft.springaddons.security.test.support.jwt;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collection;

import org.junit.runner.RunWith;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Scope;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.junit4.SpringRunner;

import com.c4_soft.springaddons.security.test.support.Defaults;

/**
 * @author Ch4mp
 *
 */
@RunWith(SpringRunner.class)
@Import(JwtAuthenticationTokenUnitTestsParent.JwtUnitTestConfig.class)
public abstract class JwtAuthenticationTokenUnitTestsParent {

	@Autowired
	BeanFactory beanFactory;

	public JwtAuthenticationTokenWebTestClientConfigurer securityWebTestClientConfigurer() {
		return beanFactory.getBean(JwtAuthenticationTokenWebTestClientConfigurer.class);
	}

	public JwtAuthenticationTokenRequestPostProcessor securityRequestPostProcessor() {
		return beanFactory.getBean(JwtAuthenticationTokenRequestPostProcessor.class);
	}

	@TestConfiguration
	public static class JwtUnitTestConfig {

		@ConditionalOnMissingBean
		@Bean
		public JwtDecoder jwtDecoder() {
			return mock(JwtDecoder.class);
		}

		@ConditionalOnMissingBean
		@Bean
		@Scope("prototype")
		public Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter() {
			final var mockAuthoritiesConverter =
					mock(Jwt2AuthoritiesConverter.class);

			when(mockAuthoritiesConverter.convert(any())).thenReturn(Defaults.GRANTED_AUTHORITIES);

			return mockAuthoritiesConverter;
		}

		@Bean
		@Scope("prototype")
		public JwtAuthenticationTokenWebTestClientConfigurer jwtAuthenticationTokenWebTestClientConfigurer(
				Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
			return new JwtAuthenticationTokenWebTestClientConfigurer(authoritiesConverter);
		}

		@Bean
		@Scope("prototype")
		public JwtAuthenticationTokenRequestPostProcessor jwtAuthenticationTokenRequestPostProcessor(
				Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
			return new JwtAuthenticationTokenRequestPostProcessor(authoritiesConverter);
		}

		private static interface Jwt2AuthoritiesConverter extends Converter<Jwt, Collection<GrantedAuthority>> {
		}
	}

}
