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
package com.c4_soft.springaddons.security.oauth2.test;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
public class Defaults {
	private Defaults() {
	}

	public static final String SUBJECT = "user";

	public static final String AUTH_NAME = "user";

	public static final List<String> SCOPES = List.of();

	public static final List<String> AUTHORITIES = List.of();

	public static final String BEARER_TOKEN_VALUE = "Bearer test token";

	public static final String JWT_VALUE = "jwt.test.token";

	public static final Set<GrantedAuthority> GRANTED_AUTHORITIES =
			Collections.unmodifiableSet(AUTHORITIES.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet()));

}
