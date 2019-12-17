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

package com.c4_soft.springaddons.test.security.web.servlet.request;

import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Scope;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;

import com.c4_soft.oauth2.rfc7662.IntrospectionClaimSet;
import com.c4_soft.springaddons.test.security.support.introspection.IntrospectionClaimSetAuthenticationRequestPostProcessor;

/**
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 *
 */
@Import(ServletIntrospectionClaimSetAuthenticationUnitTestingSupport.UnitTestConfig.class)
public class ServletIntrospectionClaimSetAuthenticationUnitTestingSupport
		extends
		ServletClaimSetAuthenticationUnitTestingSupport<IntrospectionClaimSet, IntrospectionClaimSetAuthenticationRequestPostProcessor> {

	@Override
	public IntrospectionClaimSetAuthenticationRequestPostProcessor authentication() {
		return beanFactory.getBean(IntrospectionClaimSetAuthenticationRequestPostProcessor.class);
	}

	@TestConfiguration
	public static class UnitTestConfig {

		@Bean
		@Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
		public IntrospectionClaimSetAuthenticationRequestPostProcessor claimSetAuthenticationRequestPostProcessor(
				Converter<Map<String, Object>, Set<GrantedAuthority>> authoritiesConverter) {
			return new IntrospectionClaimSetAuthenticationRequestPostProcessor(authoritiesConverter);
		}

		@Bean
		public ServletIntrospectionClaimSetAuthenticationUnitTestingSupport testingSupport() {
			return new ServletIntrospectionClaimSetAuthenticationUnitTestingSupport();
		}
	}

}
