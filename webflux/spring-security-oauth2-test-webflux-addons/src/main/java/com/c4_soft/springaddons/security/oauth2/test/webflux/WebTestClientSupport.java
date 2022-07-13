/*
 * Copyright 2020 Jérôme Wacongne
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
package com.c4_soft.springaddons.security.oauth2.test.webflux;

import java.nio.charset.Charset;

import org.springframework.http.MediaType;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.reactive.server.WebTestClient.ResponseSpec;
import org.springframework.test.web.reactive.server.WebTestClientConfigurer;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;

/**
 * You may configure in your test properties:
 * <ul>
 * <li>{@code com.c4-soft.springaddons.test.web.default-charset} defaulted to utf-8
 * <li>{@code com.c4-soft.springaddons.test.web.default-media-type} defaulted to application+json
 * </ul>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class WebTestClientSupport {

	private MediaType mediaType;

	private Charset charset;

	private WebTestClient delegate;

	public WebTestClientSupport(WebTestClientProperties webTestClientProperties, WebTestClient webTestClient, SpringAddonsSecurityProperties securityProperties) {
		this.mediaType = MediaType.valueOf(webTestClientProperties.getDefaultMediaType());
		this.charset = Charset.forName(webTestClientProperties.getDefaultCharset());
		this.delegate = webTestClient;
		this.setCsrf(securityProperties.isCsrfEnabled());
	}

	/**
	 * @param  mediaType override configured default media-type
	 * @return
	 */
	public WebTestClientSupport setMediaType(MediaType mediaType) {
		this.mediaType = mediaType;
		return this;
	}

	/**
	 * @param  charset override configured default charset
	 * @return
	 */
	public WebTestClientSupport setCharset(Charset charset) {
		this.charset = charset;
		return this;
	}

	public ResponseSpec get(MediaType accept, String uriTemplate, Object... uriVars) {
		return delegate.get().uri(uriTemplate, uriVars).accept(accept).exchange();
	}

	public ResponseSpec get(String uriTemplate, Object... uriVars) {
		return get(new MediaType(mediaType, charset), uriTemplate, uriVars);
	}

	public <T> ResponseSpec post(T payload, MediaType contentType, Charset charset, MediaType accept, String uriTemplate, Object... uriVars) {
		return delegate.post().uri(uriTemplate, uriVars).accept(accept).contentType(new MediaType(contentType, charset)).bodyValue(payload).exchange();
	}

	public <T> ResponseSpec post(T payload, String uriTemplate, Object... uriVars) {
		return post(payload, mediaType, charset, mediaType, uriTemplate, uriVars);
	}

	public <T> ResponseSpec put(T payload, MediaType contentType, Charset charset, String uriTemplate, Object... uriVars) {
		return delegate.put().uri(uriTemplate, uriVars).contentType(new MediaType(contentType, charset)).bodyValue(payload).exchange();
	}

	public <T> ResponseSpec put(T payload, String uriTemplate, Object... uriVars) {
		return put(payload, mediaType, charset, uriTemplate, uriVars);
	}

	public <T> ResponseSpec patch(T payload, MediaType contentType, Charset charset, String uriTemplate, Object... uriVars) {
		return delegate.patch().uri(uriTemplate, uriVars).contentType(new MediaType(contentType, charset)).bodyValue(payload).exchange();
	}

	public <T> ResponseSpec patch(T payload, String uriTemplate, Object... uriVars) {
		return patch(payload, mediaType, charset, uriTemplate, uriVars);
	}

	public ResponseSpec delete(String uriTemplate, Object... uriVars) {
		return delegate.delete().uri(uriTemplate, uriVars).exchange();
	}

	public WebTestClientSupport mutateWith(WebTestClientConfigurer configurer) {
		delegate = delegate.mutateWith(configurer);
		return this;
	}
	
	public WebTestClientSupport setCsrf(boolean isCsrf) {
		delegate.mutateWith(SecurityMockServerConfigurers.csrf());
		return this;
	}
}
