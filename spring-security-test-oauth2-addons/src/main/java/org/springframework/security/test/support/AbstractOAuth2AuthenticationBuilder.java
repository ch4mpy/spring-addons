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
package org.springframework.security.test.support;

import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class AbstractOAuth2AuthenticationBuilder<T extends AbstractOAuth2AuthenticationBuilder<T, U>, U> {

	protected String tokenValue;
	protected final Map<String, Object> attributes;
	protected Converter<U, Collection<GrantedAuthority>> authoritiesConverter;

	public AbstractOAuth2AuthenticationBuilder(Converter<U, Collection<GrantedAuthority>> authoritiesConverter, String tokenValue) {
		this.attributes = new HashMap<>();
		this.authoritiesConverter = authoritiesConverter;
		this.tokenValue = tokenValue;
	}

	public T attribute(String name, Object value) {
		Assert.hasText(name, "attribute name must be non empty");
		this.attributes.put(name, value);
		return downCast();
	}

	/**
	 * Clears existing attributes before adding new ones
	 * @param attributes attributes to replace current ones with
	 * @return token builder to further configure
	 */
	public T attributes(Map<String, Object> attributes) {
		Assert.notNull(attributes, "attributes must be non null");
		this.attributes.clear();
		this.attributes.putAll(attributes);
		return downCast();
	}

	protected T authoritiesConverter(Converter<U, Collection<GrantedAuthority>> authoritiesConverter) {
		this.authoritiesConverter = authoritiesConverter;
		return downCast();
	}

	public T tokenValue(String tokenValue) {
		this.tokenValue = tokenValue;
		return downCast();
	}

	Collection<GrantedAuthority> getAuthorities(U token) {
		return authoritiesConverter.convert(token);
	}

	@SuppressWarnings("unchecked")
	protected T downCast() {
		return (T) this;
	}

	protected static final Map<String, Object> putIfNotEmpty(String key, Instant value, Map<String, Object> map) {
		if (value != null) {
			map.put(key, value);
		}
		return map;
	}
}
