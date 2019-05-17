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
package org.springframework.security.test.support.missingpublicapi;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.oauth2.core.ClaimAccessor;

public class TokenProperties extends HashMap<String, Object> implements ClaimAccessor {
	private static final long serialVersionUID = -6545762106394468520L;

	public TokenProperties(Map<String, Object> tokenAttributes) {
		super(tokenAttributes);
	}

	public TokenProperties() {
		super();
	}

	@Override
	public Map<String, Object> getClaims() {
		return this;
	}

}