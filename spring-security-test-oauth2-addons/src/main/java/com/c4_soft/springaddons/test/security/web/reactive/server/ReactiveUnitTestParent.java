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

package com.c4_soft.springaddons.test.security.web.reactive.server;

import org.junit.runner.RunWith;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;

import com.c4_soft.springaddons.test.web.reactive.support.WebTestClientSupport;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@RunWith(SpringRunner.class)
public abstract class ReactiveUnitTestParent {

	@Autowired
	protected BeanFactory beanFactory;

	@Value("${com.c4-soft.springaddons.test.web.default-media-type:application/json}")
	protected String defaultMediaType;

	private final Object[] controller;

	/**
	 * @param controller an instance of the {@code @Controller} to unit-test
	 */
	public ReactiveUnitTestParent(Object... controller) {
		this.controller = controller;
	}

	/**
	 * @return a pre-configured WebTestClient with helper method for most common REST calls
	 */
	public WebTestClientSupport webTestClient() {
		return new WebTestClientSupport(MediaType.valueOf(defaultMediaType), controller);
	}

}
