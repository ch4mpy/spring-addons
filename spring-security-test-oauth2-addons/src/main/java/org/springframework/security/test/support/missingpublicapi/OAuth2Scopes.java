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

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class OAuth2Scopes extends HashSet<String> {
	private static final long serialVersionUID = -1441284130387642881L;

	private static final String SEPARATOR = " ";
	private static final String PROPERTY_NAME = "scope";

	public OAuth2Scopes(Collection<String> values) {
		super(values);
	}

	public OAuth2Scopes() {
		super();
	}

	public Map<String, Object> putIn(Map<String, Object> tokenProperties) {
		tokenProperties.put(PROPERTY_NAME, this.stream().collect(Collectors.joining(SEPARATOR)));
		return tokenProperties;
	}

	public static Converter<Map<String, Object>, OAuth2Scopes> converter() {
		return properties -> {
			final String scopeProperty = (String) properties.get(PROPERTY_NAME);
			if(scopeProperty == null) {
				return new OAuth2Scopes();
			}
			return new OAuth2Scopes(Stream.of(scopeProperty.split(SEPARATOR)).collect(Collectors.toSet()));
		};
	}

	public static OAuth2Scopes from(Map<String, Object> tokenProperties) {
		return converter().convert(tokenProperties);
	}
}
