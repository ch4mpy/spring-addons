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
package com.c4_soft.springaddons.security.oauth2.test.mockmvc;

import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Helper class for servlet {@code @Controller} unit-tests using security flow
 * API (useless if using annotations).<br>
 * Might be used either as a parent class (easier) or collaborator (requires
 * some test configuration).<br>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@ComponentScan(basePackageClasses = { MockMvcSupport.class })
public class ServletUnitTestingSupport {

	@Autowired
	protected BeanFactory beanFactory;

	/**
	 * @return ready to use {@link MockMvcSupport}, a {@link MockMvc} wrapper
	 *         providing helpers for common REST requests
	 */
	public MockMvcSupport mockMvc() {
		return beanFactory.getBean(MockMvcSupport.class);
	}

}
