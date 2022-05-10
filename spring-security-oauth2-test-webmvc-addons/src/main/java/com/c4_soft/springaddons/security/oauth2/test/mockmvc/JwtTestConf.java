/*
 * Copyright 2020 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may
 * obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */
package com.c4_soft.springaddons.security.oauth2.test.mockmvc;

import static org.mockito.Mockito.mock;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * @author ch4mp Test configuration to mock JwtDecoder
 */
@TestConfiguration(proxyBeanMethods = false)
@Order(Ordered.LOWEST_PRECEDENCE)
public class JwtTestConf {

	@Bean
	public JwtDecoder jwtDecoder() {
		return mock(JwtDecoder.class);
	}

}
