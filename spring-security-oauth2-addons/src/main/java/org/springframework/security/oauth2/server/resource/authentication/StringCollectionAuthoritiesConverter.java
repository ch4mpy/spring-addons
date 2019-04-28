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
package org.springframework.security.oauth2.server.resource.authentication;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.StringUtils;

/**
 * Quite flexible converter to parse OAuth2 token attributes (AKA claims) and extract authorities.
 *
 * Usage:<ul>
 * <li>provide the name(s) of attribute(s) you want to be scanned for authorities. Default is ["scope", "scp", "authorities"]. You should narrow that down.</li>
 * <li>provide the prefix you want for authorities. Default is empty (while Spring adds "SCOPE_" prefix)</li>
 * </ul>
 *
 * All provided attributes are scanned and recognized authorities are merged into a single {@code Set}.
 *
 * Recognized authorities types are {@code Collection<String>} and space separated {@code String}s as spring-security does, but also {@code Collection<GrantedAuthority>}.
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class StringCollectionAuthoritiesConverter implements Converter<Collection<String>, Collection<GrantedAuthority>> {

	private final String prefix;

	/**
	 * @param prefix each authority will start with
	 */
	public StringCollectionAuthoritiesConverter(String prefix) {
		this.prefix = prefix;
	}

	/**
	 * Defaults to <b>no</b> prefix
	 */
	public StringCollectionAuthoritiesConverter() {
		this(null);
	}

	@Override
	public Collection<GrantedAuthority> convert(Collection<String> source) {
		return source.stream()
				.map(authority -> StringUtils.isEmpty(prefix) ? authority : prefix + authority)
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toSet());
	}
}
