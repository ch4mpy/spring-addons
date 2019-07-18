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

package com.c4_soft.springaddons.security.test.support;

public class AuthoritiesConverterNotAMockException extends RuntimeException {
	private static final long serialVersionUID = 535445516846968187L;

	public AuthoritiesConverterNotAMockException() {
		super("Configured `authoritiesConverter` must be a mock for `authorities` to be set directly. Please set claims instead if you configured a \"real\" authorities converter.");
	}
}