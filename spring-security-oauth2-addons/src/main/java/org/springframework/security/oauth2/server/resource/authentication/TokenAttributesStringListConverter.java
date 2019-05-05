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
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;
import org.springframework.util.StringUtils;

/**
 * <p>Converter to parse OAuth2 token attributes (AKA claims) and extract a {@code List<String>} out of it.
 * This can be useful to parse scopes and authorities names, but also any string collection spread across one or more attributes.
 * </p>
 *
 * Sample (report to unit tests for more):
 * <pre>
 * final var converter = new TokenAttributesStringListConverter.Builder().prefix("SCOPE_").build();
 * final Map&lt;String, Object&gt; tokenAttributes = Map.of("scp", "message:read message:write");
 * final List&lt;String&gt; scopes = converter.convert(tokenAttributes);
 * </pre>
 *
 * <p>All provided attributes are scanned and extracted strings are merged into a single {@code List}.</p>
 *
 * <p>Elements are extracted from {@code Collection<Object>}, {@code Object[]} and space separated {@code String}s using {@code .toString()}.</p>
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class TokenAttributesStringListConverter implements Converter<Map<String, Object>, List<String>> {

	private final Collection<String> scanedAttributes;
	private final String elementsRegex;

	/**
	 * @see Builder
	 * @param scanedAttributes name of the token attribute to extract elements from
	 * @param elementsRegex passed to {@code String::split} to separate elements  stored in single list
	 */
	public TokenAttributesStringListConverter(Collection<String> scanedAttributes, String elementsRegex) {
		this.scanedAttributes = Collections.unmodifiableSet(new HashSet<>(scanedAttributes));
		this.elementsRegex = elementsRegex;
	}

	@Override
	public List<String> convert(Map<String, Object> source) {
		return scanedAttributes.stream()
				.map(source::get)
				.flatMap(TokenAttributesStringListConverter::elementsToSplit)
				.filter(s -> !StringUtils.isEmpty(s))
				.flatMap(s -> Stream.of(s.split(elementsRegex)))
				.filter(s -> !StringUtils.isEmpty(s))
				.collect(Collectors.toList());
	}

	private static Stream<String> elementsToSplit(Object attribute) {
		if(attribute instanceof Collection) {
			return ((Collection<?>) attribute).stream().map(TokenAttributesStringListConverter::nullSafeToString);
		}
		if(attribute instanceof Object[]) {
			return Stream.of((Object[]) attribute).map(TokenAttributesStringListConverter::nullSafeToString);
		}
		return Stream.of(nullSafeToString(attribute));
	}

	private static String nullSafeToString(Object o) {
		return o == null ? null : o.toString();
	}

	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Builder for TokenAttributesStringListConverter.
	 * Sample usage:
	 * <pre>
	 * &64;Bean
	 * public TokenAttributesStringListConverter tokenAttributesScopesConverter() {
	 *     TokenAttributesStringListConverter.builder().build();
	 * }
	 * </pre>
	 * Defaults:<ul>
	 * <li>scanedAttributes to ["scope", "scp"]: string default for scopes and authorities</li>
	 * <li>prefix to null: no prefix, which <b>differs from spring default "SCOPE_"</b></li>
	 * <li>elementsRegex to ": search for space separated elements</li>
	 * </ul>
	 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
	 *
	 */
	public static class Builder {
		private Set<String> scanedAttributes;
		private String elementsRegex;

		public Builder() {
			this.scanedAttributes = Set.of("scope", "scp");
			this.elementsRegex = " ";
		}

		public Builder scanedAttributes(Collection<String> scanedAttributes) {
			this.scanedAttributes = new HashSet<>(scanedAttributes);
			return this;
		}

		public Builder scanedAttributes(String... scanedAttributes) {
			return scanedAttributes(Stream.of(scanedAttributes).collect(Collectors.toSet()));
		}

		public Builder elementsRegex(String elementsRegex) {
			this.elementsRegex = elementsRegex;
			return this;
		}

		public TokenAttributesStringListConverter build() {
			return new TokenAttributesStringListConverter(scanedAttributes, elementsRegex);
		}
	}
}
