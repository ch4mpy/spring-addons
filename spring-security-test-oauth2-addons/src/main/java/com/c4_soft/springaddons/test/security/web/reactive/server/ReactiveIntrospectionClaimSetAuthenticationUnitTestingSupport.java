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

import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Scope;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;

import com.c4_soft.springaddons.test.security.support.Defaults;
import com.c4_soft.springaddons.test.security.support.introspection.IntrospectionClaimSetAuthenticationWebTestClientConfigurer;

/**
 * <p>
 * A {@link ReactiveUnitTestingSupport} with additional helper methods to configure test {@code Authentication}
 * instance, it being a {@code OAuth2ClaimSetAuthentication<IntrospectionClaimSet>}.
 * </p>
 *
 * Usage as test class parent (note default constructor providing parent with controller under test instance):
 * 
 * <pre>
 * &#64;RunWith(SpringRunner.class)
 * public class TestControllerTests extends ReactiveIntrospectionClaimSetAuthenticationUnitTestingSupport {
 *
 * 	public TestControllerTests() {
 * 		super(new TestController());
 * 	}
 *
 * 	&#64;Test
 * 	public void testDemo() {
 * 		webTestClient().with(authentication().name("ch4mpy").authorities("message:read"))
 * 				.get("/authentication")
 * 				.expectStatus()
 * 				.isOk();
 * 	}
 * }
 * </pre>
 *
 * Same can be achieved using it as collaborator (note additional imported test configuration):
 * 
 * <pre>
 * &#64;RunWith(SpringRunner.class)
 * &#64;Import(TestControllerTests.TestConfig.class)
 * public class TestControllerTests {
 *
 * 	&#64;Autowired
 * 	private ReactiveIntrospectionClaimSetAuthenticationUnitTestingSupport testingSupport;
 *
 * 	&#64;Test
 * 	public void testDemo() {
 * 		testingSupport.webTestClient()
 * 				.with(testingSupport.authentication().name("ch4mpy").authorities("message:read"))
 * 				.get("/authentication")
 * 				.expectStatus()
 * 				.isOk();
 * 	}
 *
 * 	&#64;Import(ReactiveIntrospectionClaimSetAuthenticationUnitTestingSupport.UnitTestConfig.class)
 * 	public static final class TestConfig {
 *
 * 		&#64;Bean
 * 		public ReactiveIntrospectionClaimSetAuthenticationUnitTestingSupport testSupport() {
 * 			return new ReactiveIntrospectionClaimSetAuthenticationUnitTestingSupport(new TestController());
 * 		}
 * 	}
 * }
 * </pre>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 *
 */
@Import(ReactiveIntrospectionClaimSetAuthenticationUnitTestingSupport.UnitTestConfig.class)
public class ReactiveIntrospectionClaimSetAuthenticationUnitTestingSupport extends ReactiveUnitTestingSupport {

	/**
	 * @param controller an instance of the {@code @Controller} under test
	 */
	public ReactiveIntrospectionClaimSetAuthenticationUnitTestingSupport(Object controller) {
		super(controller);
	}

	public IntrospectionClaimSetAuthenticationWebTestClientConfigurer authentication() {
		return beanFactory.getBean(IntrospectionClaimSetAuthenticationWebTestClientConfigurer.class);
	}

	public IntrospectionClaimSetAuthenticationWebTestClientConfigurer
			authentication(Consumer<Map<String, Object>> claimsConsumer) {
		final var webTestClientConfigurer =
				beanFactory.getBean(IntrospectionClaimSetAuthenticationWebTestClientConfigurer.class);
		webTestClientConfigurer.claims(claimsConsumer);
		return webTestClientConfigurer;
	}

	@TestConfiguration
	public static class UnitTestConfig {

		@ConditionalOnMissingBean
		@Bean
		@Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
		public Converter<Map<String, Object>, Set<GrantedAuthority>> authoritiesConverter() {
			final var mockAuthoritiesConverter = mock(IntrospectionClaimSet2AuthoritiesConverter.class);

			when(mockAuthoritiesConverter.convert(any())).thenReturn(Defaults.GRANTED_AUTHORITIES);

			return mockAuthoritiesConverter;
		}

		@Bean
		@Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
		public IntrospectionClaimSetAuthenticationWebTestClientConfigurer
				oAuth2IntrospectionAuthenticationTokenWebTestClientConfigurer(
						Converter<Map<String, Object>, Set<GrantedAuthority>> authoritiesConverter) {
			return new IntrospectionClaimSetAuthenticationWebTestClientConfigurer(authoritiesConverter);
		}

		private interface IntrospectionClaimSet2AuthoritiesConverter
				extends
				Converter<Map<String, Object>, Set<GrantedAuthority>> {
		}
	}

}
