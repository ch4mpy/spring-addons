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

import java.util.Set;
import java.util.function.Consumer;

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

import com.c4_soft.oauth2.rfc7662.IntrospectionClaimSet;
import com.c4_soft.springaddons.security.test.support.Defaults;

/**
 * @author Ch4mp
 *
 */
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = IntrospectionClaimSetAuthenticationUnitTestsParent.IntrospectionUnitTestConfig.class)
public class IntrospectionClaimSetAuthenticationUnitTestsParent {

	@Autowired
	BeanFactory beanFactory;

	public IntrospectionClaimSetAuthenticationRequestPostProcessor securityRequestPostProcessor() {
		return beanFactory.getBean(IntrospectionClaimSetAuthenticationRequestPostProcessor.class);
	}

	public IntrospectionClaimSetAuthenticationRequestPostProcessor securityRequestPostProcessor(
			Consumer<IntrospectionClaimSet.Builder<?>> claimsConsumer) {
		final var requestPostProcessor = beanFactory.getBean(IntrospectionClaimSetAuthenticationRequestPostProcessor.class);
		requestPostProcessor.claims(claimsConsumer);
		return requestPostProcessor;
	}

	public IntrospectionClaimSetAuthenticationWebTestClientConfigurer securityWebTestClientConfigurer() {
		return beanFactory.getBean(IntrospectionClaimSetAuthenticationWebTestClientConfigurer.class);
	}

	public IntrospectionClaimSetAuthenticationWebTestClientConfigurer securityWebTestClientConfigurer(
			Consumer<IntrospectionClaimSet.Builder<?>> claimsConsumer) {
		final var webTestClientConfigurer = beanFactory.getBean(IntrospectionClaimSetAuthenticationWebTestClientConfigurer.class);
		webTestClientConfigurer.claims(claimsConsumer);
		return webTestClientConfigurer;
	}

	@TestConfiguration
	public static class IntrospectionUnitTestConfig {

		@ConditionalOnMissingBean
		@Bean
		@Scope("prototype")
		public Converter<IntrospectionClaimSet, Set<GrantedAuthority>> authoritiesConverter() {
			final var mockAuthoritiesConverter = mock(IntrospectionClaimSet2AuthoritiesConverter.class);

			when(mockAuthoritiesConverter.convert(any())).thenReturn(Defaults.GRANTED_AUTHORITIES);

			return mockAuthoritiesConverter;
		}

		@Bean
		@Scope("prototype")
		public IntrospectionClaimSetAuthenticationWebTestClientConfigurer oAuth2IntrospectionAuthenticationTokenWebTestClientConfigurer(
				Converter<IntrospectionClaimSet, Set<GrantedAuthority>> authoritiesConverter) {
			return new IntrospectionClaimSetAuthenticationWebTestClientConfigurer(authoritiesConverter);
		}

		@Bean
		@Scope("prototype")
		public IntrospectionClaimSetAuthenticationRequestPostProcessor introspectionClaimSetAuthenticationRequestPostProcessor(
				Converter<IntrospectionClaimSet, Set<GrantedAuthority>> authoritiesConverter) {
			return new IntrospectionClaimSetAuthenticationRequestPostProcessor(authoritiesConverter);
		}

		private static interface IntrospectionClaimSet2AuthoritiesConverter extends Converter<IntrospectionClaimSet, Set<GrantedAuthority>> {
		}
	}

}
