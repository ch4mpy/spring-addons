/*
 * Copyright 2020 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.c4_soft.springaddons.security.oauth2.test.webflux;

import java.nio.charset.Charset;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.context.annotation.Scope;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.reactive.server.WebTestClient.ResponseSpec;
import org.springframework.test.web.reactive.server.WebTestClientConfigurer;

/**
 * You may configure in your test properties:<ul>
 * <li>{@code com.c4-soft.springaddons.test.web.default-charset} defaulted to utf-8
 * <li>{@code com.c4-soft.springaddons.test.web.default-media-type} defaulted to application+json
 * </ul>
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@TestComponent
@Scope("prototype")
public class WebTestClientSupport {

	private final String defaultMediaType;

	private final String defaultCharset;

	private WebTestClient delegate;

	@Autowired
	public WebTestClientSupport(
			@Value("${com.c4-soft.springaddons.test.web.default-charset:utf-8}") String defaultMediaType,
			@Value("${com.c4-soft.springaddons.test.web.default-media-type:application+json}") String defaultCharset,
			WebTestClient webTestClient) {
		this.defaultMediaType = defaultMediaType;
		this.defaultCharset = defaultCharset;
		this.delegate = webTestClient;
	}

	public ResponseSpec get(MediaType accept, String uriTemplate, Object... uriVars) {
		return delegate.get().uri(uriTemplate, uriVars).accept(accept).exchange();
	}

	public ResponseSpec get(String uriTemplate, Object... uriVars) {
		return get(new MediaType(defaultMediaType, defaultCharset), uriTemplate, uriVars);
	}

	public <T> ResponseSpec post(
			T payload,
			MediaType contentType,
			Charset charset,
			MediaType accept,
			String uriTemplate,
			Object... uriVars) {
		return delegate.post()
				.uri(uriTemplate, uriVars)
				.accept(accept)
				.contentType(new MediaType(contentType, charset))
				.bodyValue(payload)
				.exchange();
	}

	public <T> ResponseSpec post(T payload, String uriTemplate, Object... uriVars) {
		return post(payload, defaultMediaType, defaultCharset, defaultMediaType, uriTemplate, uriVars);
	}

	public <T> ResponseSpec
			put(T payload, MediaType contentType, Charset charset, String uriTemplate, Object... uriVars) {
		return delegate.put()
				.uri(uriTemplate, uriVars)
				.contentType(new MediaType(contentType, charset))
				.bodyValue(payload)
				.exchange();
	}

	public <T> ResponseSpec put(T payload, String uriTemplate, Object... uriVars) throws Exception {
		return put(payload, defaultMediaType, defaultCharset, uriTemplate, uriVars);
	}

	public <T> ResponseSpec
			patch(T payload, MediaType contentType, Charset charset, String uriTemplate, Object... uriVars) {
		return delegate.patch()
				.uri(uriTemplate, uriVars)
				.contentType(new MediaType(contentType, charset))
				.bodyValue(payload)
				.exchange();
	}

	public <T> ResponseSpec patch(T payload, String uriTemplate, Object... uriVars) throws Exception {
		return patch(payload, defaultMediaType, defaultCharset, uriTemplate, uriVars);
	}

	public <T> ResponseSpec delete(String uriTemplate, Object... uriVars) throws Exception {
		return delegate.delete().uri(uriTemplate, uriVars).exchange();
	}

	public WebTestClientSupport mutateWith(WebTestClientConfigurer configurer) {
		delegate = delegate.mutateWith(configurer);
		return this;
	}
}
