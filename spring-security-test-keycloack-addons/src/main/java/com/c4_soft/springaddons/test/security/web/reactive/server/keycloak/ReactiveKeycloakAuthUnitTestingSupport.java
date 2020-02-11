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

package com.c4_soft.springaddons.test.security.web.reactive.server.keycloak;

import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Scope;

import com.c4_soft.springaddons.test.security.web.reactive.server.ReactiveUnitTestingSupport;

/**
 * <p>
 * A {@link ReactiveUnitTestingSupport} with additional helper methods to
 * configure test {@code Authentication} instance, it being an
 * {@code OAuth2IntrospectionAuthenticationToken}.
 * </p>
 *
 * Usage as test class parent (note default constructor providing parent with
 * controller under test instance):
 *
 * <pre>
 * &#64;RunWith(SpringRunner.class)
 * public class TestControllerTests extends ReactiveOAuth2IntrospectionAuthenticationTokenUnitTestingSupport {
 *
 * 	private TestController controller = new TestController();
 *
 * 	&#64;Test
 * 	public void testDemo() {
 * 		webTestClient(controller).with(authentication().name("ch4mpy").authorities("message:read"))
 * 				.get("/authentication").expectStatus().isOk();
 * 	}
 * }
 * </pre>
 *
 * Same can be achieved using it as collaborator (note additional imported test
 * configuration):
 *
 * <pre>
 * &#64;RunWith(SpringRunner.class)
 * &#64;Import(TestControllerTests.TestConfig.class)
 * public class TestControllerTests {
 *
 * 	&#64;Autowired
 * 	private TestController controller;
 *
 *   &#64;Autowired
 *   private ReactiveOAuth2IntrospectionAuthenticationTokenUnitTestingSupport testingSupport;
 *
 *   &#64;Test
 *   public void testDemo() {
 *     testingSupport
 *       .webTestClient(controller)
 *       .with(testingSupport.authentication().name("ch4mpy").authorities("message:read"))
 *       .get("/authentication")
 *       .expectStatus().isOk();
 *   }
 *
 *   &#64;Import(ReactiveOAuth2IntrospectionAuthenticationTokenUnitTestingSupport.UnitTestConfig.class)
 *   public static final class TestConfig {
 *
 * 		&#64;Bean
 * 		public TestController controller() {
 * 			return new new TestController();
 * 		}
 *
 *     &#64;Bean
 *     public ReactiveOAuth2IntrospectionAuthenticationTokenUnitTestingSupport testSupport() {
 *       return new ReactiveOAuth2IntrospectionAuthenticationTokenUnitTestingSupport();
 *     }
 *   }
 * }
 * </pre>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 *
 */
@Import(ReactiveKeycloakAuthUnitTestingSupport.UnitTestConfig.class)
public class ReactiveKeycloakAuthUnitTestingSupport extends ReactiveUnitTestingSupport {

	public KeycloakAuthWebTestClientConfigurer authentication() {
		return beanFactory.getBean(KeycloakAuthWebTestClientConfigurer.class);
	}

	@TestConfiguration
	public static class UnitTestConfig {

		@Bean
		@Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
		public KeycloakAuthWebTestClientConfigurer keycloakAuthWebTestClientConfigurer() {
			return new KeycloakAuthWebTestClientConfigurer();
		}
	}

}
