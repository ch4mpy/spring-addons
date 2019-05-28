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
package com.c4soft.springaddons.security.test.support.missingpublicapi;

import java.util.Map;
import java.util.function.Consumer;

import com.c4soft.oauth2.rfc7662.IntrospectionClaimSet;

/**
 * A class to put introspection token value and claims together
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
public class OAuth2IntrospectionToken {

	private final String value;
	private final IntrospectionClaimSet attributes;

	public OAuth2IntrospectionToken(String value, Map<String, Object> attributes) {
		super();
		this.value = value;
		this.attributes = new IntrospectionClaimSet(attributes);
	}

	public String getTokenValue() {
		return this.value;
	}

	public IntrospectionClaimSet getAttributes() {
		return attributes;
	}

	public static OAuth2IntrospectionTokenBuilder<?> builder() {
		return new OAuth2IntrospectionTokenBuilder<>();
	}

	/**
	 *
	 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
	 *
	 * @param <T> capture for extending class type
	 */
	public static class OAuth2IntrospectionTokenBuilder<T extends OAuth2IntrospectionTokenBuilder<T>> {

		private String value;
		private final IntrospectionClaimSet.Builder<?> attributes;

		public OAuth2IntrospectionTokenBuilder() {
			this.attributes = IntrospectionClaimSet.builder();
		}

		public T attributes(Consumer<IntrospectionClaimSet.Builder<?>> attributesBuilderConsumer) {
			attributesBuilderConsumer.accept(this.attributes);
			return downcast();
		}

		public T value(String tokenValue) {
			this.value = tokenValue;
			return downcast();
		}

		public OAuth2IntrospectionToken build() {
			return new OAuth2IntrospectionToken(value, attributes.build());
		}

		@SuppressWarnings("unchecked")
		protected T downcast() {
			return (T) this;
		}
	}
}
