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

package com.c4_soft.springaddons.security.test.support.introspection;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collection;
import java.util.Map;

import org.junit.runner.RunWith;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Scope;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import com.c4_soft.springaddons.security.test.support.Defaults;

/**
 * @author Ch4mp
 *
 */
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = OAuth2IntrospectionAuthenticationTokenUnitTestsParent.IntrospectionUnitTestConfig.class)
public class OAuth2IntrospectionAuthenticationTokenUnitTestsParent {

	@Autowired
	BeanFactory beanFactory;

	public OAuth2IntrospectionAuthenticationTokenWebTestClientConfigurer
			securityWebTestClientConfigurer() {
		return beanFactory.getBean(OAuth2IntrospectionAuthenticationTokenWebTestClientConfigurer.class);
	}

	public OAuth2IntrospectionAuthenticationTokenRequestPostProcessor
			securityRequestPostProcessor() {
		return beanFactory.getBean(OAuth2IntrospectionAuthenticationTokenRequestPostProcessor.class);
	}

	@TestConfiguration
	public static class IntrospectionUnitTestConfig {

		@ConditionalOnMissingBean
		@Bean
		@Scope("prototype")
		public Converter<Map<String, Object>, Collection<GrantedAuthority>> authoritiesConverter() {
			final var mockAuthoritiesConverter = mock(IntrospectedClaims2AuthoritiesConverter.class);

			when(mockAuthoritiesConverter.convert(any())).thenReturn(Defaults.GRANTED_AUTHORITIES);

			return mockAuthoritiesConverter;
		}

		@Bean
		@Scope("prototype")
		public OAuth2IntrospectionAuthenticationTokenWebTestClientConfigurer oAuth2IntrospectionAuthenticationTokenWebTestClientConfigurer(
				Converter<Map<String, Object>, Collection<GrantedAuthority>> authoritiesConverter) {
			return new OAuth2IntrospectionAuthenticationTokenWebTestClientConfigurer(authoritiesConverter);
		}

		@Bean
		@Scope("prototype")
		public OAuth2IntrospectionAuthenticationTokenRequestPostProcessor oAuth2IntrospectionAuthenticationTokenRequestPostProcessor(
				Converter<Map<String, Object>, Collection<GrantedAuthority>> authoritiesConverter) {
			return new OAuth2IntrospectionAuthenticationTokenRequestPostProcessor(authoritiesConverter);
		}

		private static interface IntrospectedClaims2AuthoritiesConverter extends Converter<Map<String, Object>, Collection<GrantedAuthority>> {
		}
	}

}
