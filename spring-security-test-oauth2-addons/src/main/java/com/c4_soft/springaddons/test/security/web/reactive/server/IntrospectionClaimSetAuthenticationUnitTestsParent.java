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

package com.c4_soft.springaddons.test.security.web.reactive.server;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Set;
import java.util.function.Consumer;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Scope;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;

import com.c4_soft.oauth2.rfc7662.IntrospectionClaimSet;
import com.c4_soft.springaddons.test.security.support.Defaults;
import com.c4_soft.springaddons.test.security.support.introspection.IntrospectionClaimSetAuthenticationWebTestClientConfigurer;
import com.c4_soft.springaddons.test.security.web.reactive.server.IntrospectionClaimSetAuthenticationUnitTestsParent.UnitTestConfig;

/**
 * @author Ch4mp
 *
 */
@Import(UnitTestConfig.class)
public abstract class IntrospectionClaimSetAuthenticationUnitTestsParent extends ReactiveUnitTestParent {

	public IntrospectionClaimSetAuthenticationUnitTestsParent(Object controller) {
		super(controller);
	}

	public IntrospectionClaimSetAuthenticationWebTestClientConfigurer authentication() {
		return beanFactory.getBean(IntrospectionClaimSetAuthenticationWebTestClientConfigurer.class);
	}

	public IntrospectionClaimSetAuthenticationWebTestClientConfigurer authentication(
			Consumer<IntrospectionClaimSet.Builder<?>> claimsConsumer) {
		final var webTestClientConfigurer = beanFactory.getBean(IntrospectionClaimSetAuthenticationWebTestClientConfigurer.class);
		webTestClientConfigurer.claims(claimsConsumer);
		return webTestClientConfigurer;
	}

	@TestConfiguration
	public static class UnitTestConfig {

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

		private static interface IntrospectionClaimSet2AuthoritiesConverter extends Converter<IntrospectionClaimSet, Set<GrantedAuthority>> {
		}
	}

}
