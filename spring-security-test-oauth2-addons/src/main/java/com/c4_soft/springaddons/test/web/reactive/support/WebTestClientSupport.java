/*
 * Copyright 2019 Jérôme Wacongne
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

package com.c4_soft.springaddons.test.web.reactive.support;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

import org.springframework.http.MediaType;
import org.springframework.security.web.server.context.SecurityContextServerWebExchangeWebFilter;
import org.springframework.security.web.server.csrf.CsrfWebFilter;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.reactive.server.WebTestClient.ResponseSpec;
import org.springframework.test.web.reactive.server.WebTestClientConfigurer;

/**
 * <p>
 * Intended to reduce grunt code for most common use-case when using WebTestClient to test a single {@code @Controller}.
 * </p>
 * Features highlights:
 * <ul>
 * <li>auto-register CSRF filter and Spring security</li>
 * <li>register configurers with {@link #with(WebTestClientConfigurer)} (pretty useful for {@code Authentication}
 * configurers)</li>
 * <li>use HTTP verbs shortcuts to get {@link ResponseSpec} in one call when you need to configure no more than URI,
 * payload or meadia-type</li>
 * <li>fall-back to lower level method when more request configuration is required with {@link #client()} or
 * {@link #clientBuilder()}</li>
 * </ul>
 *
 * Sample usage taken from unit-tests:
 *
 * <pre>
 * public void testDefaultJwtConfigurer() {
 *     webTestClient(controller).with(jwtClaimSet()).get("/authentication")
 *             .expectStatus().isOk()
 * }
 * </pre>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class WebTestClientSupport {
	private final MediaType defaultMediaType;

	private final Charset defaultCharset;

	private final List<WebTestClientConfigurer> configurers;

	private final Object[] controller;

	/**
	 * @param controller {@code @Controller} instance under test
	 * @param defaultMediaType default media-type for {@code Accept} and {@code Content-type}
	 * @param defaultCharset default char-set for serialized content
	 */
	public WebTestClientSupport(MediaType defaultMediaType, Charset defaultCharset, Object... controller) {
		super();
		this.defaultMediaType = defaultMediaType;
		this.defaultCharset = defaultCharset;
		this.configurers = new ArrayList<>();
		this.controller = controller;
	}

	/**
	 * Apply a configurer, such as security ones, each time a {@link WebTestClient.Builder} is built
	 * @param configurer configurer to apply
	 * @return this {@link WebTestClientSupport}
	 */
	public WebTestClientSupport with(WebTestClientConfigurer configurer) {
		configurers.add(configurer);
		return this;
	}

	/**
	 * Lower level method to use when advanced query configuration is required
	 * @return {@link WebTestClient} builder with {@link CsrfWebFilter},
	 * {@link SecurityContextServerWebExchangeWebFilter} and {@code springSecurity()} configurer
	 */
	public WebTestClient.Builder clientBuilder() {
		final var builder = WebTestClient.bindToController(controller)
				.webFilter(new CsrfWebFilter(), new SecurityContextServerWebExchangeWebFilter())
				.apply(springSecurity())
				.configureClient();

		configurers.forEach(builder::apply);

		return builder;
	}

	/**
	 * Low level method to use when you need to customize more than URI, media-type and payload
	 * @return {@link WebTestClient} to configure and exchange
	 */
	public WebTestClient client() {
		return clientBuilder().build();
	}

	public ResponseSpec get(MediaType accept, String uriTemplate, Object... uriVars) {
		return client().get().uri(uriTemplate, uriVars).accept(accept).exchange();
	}

	public ResponseSpec get(String uriTemplate, Object... uriVars) {
		return get(defaultMediaType, uriTemplate, uriVars);
	}

	public <T> ResponseSpec post(
			T payload,
			MediaType contentType,
			Charset charset,
			MediaType accept,
			String uriTemplate,
			Object... uriVars) {
		return client().post()
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
		return client().put()
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
		return client().patch()
				.uri(uriTemplate, uriVars)
				.contentType(new MediaType(contentType, charset))
				.bodyValue(payload)
				.exchange();
	}

	public <T> ResponseSpec patch(T payload, String uriTemplate, Object... uriVars) throws Exception {
		return patch(payload, defaultMediaType, defaultCharset, uriTemplate, uriVars);
	}

	public <T> ResponseSpec delete(String uriTemplate, Object... uriVars) throws Exception {
		return client().delete().uri(uriTemplate, uriVars).exchange();
	}

}
