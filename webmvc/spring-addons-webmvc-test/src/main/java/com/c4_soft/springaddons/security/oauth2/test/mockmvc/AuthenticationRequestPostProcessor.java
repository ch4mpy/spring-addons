/*
 * Copyright 2019 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
 */
package com.c4_soft.springaddons.security.oauth2.test.mockmvc;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import com.c4_soft.springaddons.security.oauth2.AuthenticationBuilder;

/**
 * Redundant code for {@link Authentication} MockMvc request post-processors
 *
 * @author     Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 * @param  <T> concrete {@link Authentication} type to build and configure in test security context
 */
public interface AuthenticationRequestPostProcessor<T extends Authentication> extends RequestPostProcessor, AuthenticationBuilder<T> {
	@Override
	default MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
		SecurityContextRequestPostProcessorSupport.save(build(), request);
		return request;
	}
}
