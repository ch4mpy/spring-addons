/*
 * Copyright 2018 Jérôme Wacongne.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may
 * obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */
package com.c4_soft.springaddons.test.support.web;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.ObjectFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.http.HttpMessageConverters;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;

/**
 * Helps with HTTP requests body serialization using Spring registered message converters.
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class SerializationHelper {

	private final ObjectFactory<HttpMessageConverters> messageConverters;

	@Autowired
	public SerializationHelper(final ObjectFactory<HttpMessageConverters> messageConverters) {
		this.messageConverters = messageConverters;
	}

	/**
	 * Serializes objects (request payloads) to any media-type using registered HTTP message converters. Each acceptable converter
	 * ({@link org.springframework.http.converter.HttpMessageConverter#canWrite(Class, MediaType) converter.canWrite(payload.getClass(),
	 * mediaType)} return true) is tried until one actually succeeds at serializing.
	 *
	 * @param  <T>       payload type
	 * @param  payload   request body to serialize
	 * @param  mediaType expected body media-type
	 * @return           serialized payload in JSON, XML, or whatever media-type an HttpMessageConverter is registered for
	 */
	public <T> ByteArrayHttpOutputMessage outputMessage(final T payload, final MediaType mediaType) {
		if (payload == null) {
			return null;
		}

		@SuppressWarnings("unchecked")
		final List<HttpMessageConverter<T>> relevantConverters = messageConverters.getObject().getConverters().stream()
				.filter(converter -> converter.canWrite(payload.getClass(), mediaType)).map(c -> (HttpMessageConverter<T>) c)// safe to cast as "canWrite"...
				.collect(Collectors.toList());

		final ByteArrayHttpOutputMessage converted = new ByteArrayHttpOutputMessage();
		boolean isConverted = false;
		for (final HttpMessageConverter<T> converter : relevantConverters) {
			try {
				converted.headers.setContentType(mediaType);
				converter.write(payload, mediaType, converted);
				isConverted = true; // won't be reached if a conversion error occurs
				break; // stop iterating over converters after first successful conversion
			} catch (final IOException e) {
				// swallow exception so that next converter is tried
			}
		}

		if (!isConverted) {
			throw new ConversionFailedException("Could not convert " + payload.getClass() + " to " + mediaType.toString());
		}

		return converted;
	}

	/**
	 * Provides with a String representation of provided payload using {@code outputMessage(Object, MediaType)}
	 *
	 * @param  <T>       payload type
	 * @param  payload   request body to serialize
	 * @param  mediaType expected body media-type
	 * @return           serialized payload in JSON, XML, or whatever media-type an HttpMessageConverter is registered for
	 */
	public <T> String asString(final T payload, final MediaType mediaType) {
		return payload == null ? null : outputMessage(payload, mediaType).out.toString();
	}

	public <T> String asJsonString(final T payload) {
		return asString(payload, MediaType.APPLICATION_JSON);
	}

	public <T> String asXmlnString(final T payload) {
		return asString(payload, MediaType.APPLICATION_XML);
	}
}