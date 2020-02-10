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

package com.c4_soft.springaddons.test.security.web.servlet.request.keycloak;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

import com.c4_soft.springaddons.test.security.web.servlet.request.ServletUnitTestingSupport;

/**
 * <p>
 * A {@link ServletUnitTestingSupport} with additional helper methods to configure test {@code Authentication} instance,
 * it being an {@code KeycloakAuthenticationToken}.
 * </p>
 *
 * Usage as test class parent:
 *
 * <pre>
 * &#64;RunWith(SpringRunner.class)
 * &#64;WebMvcTest(GreetingController.class)
 * public class GreetingControllerTests extends ServletKeycloakAuthUnitTestingSupport {
 *
 * 	&#64;Test
 * 	public void testDemo() {
 * 		mockMvc().with(authentication().name("ch4mpy").authorities("message:read"))
 * 				.get("/authentication")
 * 				.expectStatus()
 * 				.isOk();
 * 	}
 * }
 * </pre>
 *
 * Same can be achieved using it as collaborator (note additional {@code @Import} statement):
 *
 * <pre>
 * &#64;RunWith(SpringRunner.class)
 * &#64;WebMvcTest(TestController.class)
 * &#64;Import(ServletKeycloakAuthUnitTestingSupport.class)
 * public class TestControllerTests {
 *
 * 	&#64;Autowired
 * 	private ServletKeycloakAuthUnitTestingSupport testingSupport;
 *
 * 	&#64;Test
 * 	public void testDemo() {
 * 		testingSupport.mockMvc()
 * 				.with(testingSupport.authentication().name("ch4mpy").authorities("message:read"))
 * 				.get("/authentication")
 * 				.expectStatus()
 * 				.isOk();
 * 	}
 * }
 * </pre>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 *
 */
@Import(ServletKeycloakAuthUnitTestingSupport.UnitTestConfig.class)
public class ServletKeycloakAuthUnitTestingSupport extends ServletUnitTestingSupport {

	public KeycloakAuthRequestPostProcessor authentication() {
		return beanFactory.getBean(KeycloakAuthRequestPostProcessor.class);
	}

	@TestConfiguration
	public static class UnitTestConfig {

		@Bean
		public KeycloakAuthRequestPostProcessor testingSupport() {
			return new KeycloakAuthRequestPostProcessor();
		}
	}

}
