/*
 * Copyright 2019 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.c4_soft.springaddons.test.security.web.servlet.request;

import org.junit.runner.RunWith;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.c4_soft.springaddons.test.web.servlet.MockMvcSupport;
import com.c4_soft.springaddons.test.web.support.SerializationHelper;

/**
 *
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@RunWith(SpringRunner.class)
@ComponentScan(basePackageClasses = { MockMvcSupport.class, SerializationHelper.class })
public abstract class ServletUnitTestParent {

	@Autowired
	protected BeanFactory beanFactory;

	/**
	 * @return ready to use {@link MockMvcSupport}, a {@link MockMvc} wrapper providing helpers for common REST requests
	 */
	public MockMvcSupport mockMvc() {
		return beanFactory.getBean(MockMvcSupport.class);
	}

}
