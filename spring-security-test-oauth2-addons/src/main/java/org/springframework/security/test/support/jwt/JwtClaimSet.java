/*
 * Copyright 2019 Jérôme Wacongne.
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
package org.springframework.security.test.support.jwt;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.oauth2.jwt.JwtClaimAccessor;

final class JwtClaimSet extends HashMap<String, Object> implements JwtClaimAccessor {
	private static final long serialVersionUID = 8276775804624275917L;

	public JwtClaimSet(Map<String, Object> claims) {
		super(claims);
	}

	public JwtClaimSet() {
		super();
	}

	@Override
	public Map<String, Object> getClaims() {
		return this;
	}
}