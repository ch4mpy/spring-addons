/*
 * Copyright 2018 Jérôme Wacongne.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
 */
package com.c4_soft.springaddons.security.oauth2.test.webmvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Scope;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.util.Assert;
import org.springframework.web.servlet.DispatcherServlet;
import com.c4_soft.springaddons.security.oidc.starter.properties.Csrf;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.test.support.web.SerializationHelper;

/**
 * <p>
 * Just another wrapper for Spring {@link MockMvc}.<br>
 * It would extend {@link MockMvc} if it was not final :-/
 * </p>
 * Highlighted features:
 * <ul>
 * <li>auto sets "Accept" and "Content-Type" headers according {@code com.c4-soft.springaddons.test.web.default-media-type} and
 * {@code com.c4-soft.springaddons.test.web.default-charset} to test properties, defaulted to {@code application/json} and {@code utf-8}</li>
 * <li>serializes request body according to Content-type using <b>registered message converters</b></li>
 * <li>provides with shortcuts to issue requests in basic but most common cases (no fancy headers, cookies, etc): get, post, patch, put and delete methods</li>
 * <li>wraps MockMvc {@link MockMvc#perform(RequestBuilder) perform} and exposes request builder helpers for advanced cases (when you need to further customize
 * {@link MockHttpServletRequestBuilder} with cookies or additional headers for instance)</li>
 * </ul>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
public class MockMvcSupport {
	private final MockMvc mockMvc;

	private final SerializationHelper conv;

	private MediaType mediaType;

	private Charset charset;

	private boolean isSecure;

	private boolean isCsrf;

	private final List<RequestPostProcessor> postProcessors;

	/**
	 * @param mockMvc             wrapped Spring MVC testing helper
	 * @param serializationHelper used to serialize payloads to requested {@code Content-type} using Spring registered message converters
	 * @param mockMvcProperties   default values for media-type, charset and https usage
	 */
	public MockMvcSupport(
			MockMvc mockMvc,
			SerializationHelper serializationHelper,
			MockMvcProperties mockMvcProperties,
			ServerProperties serverProperties,
			SpringAddonsOidcProperties addonsProperties) {
		this.mockMvc = mockMvc;
		this.conv = serializationHelper;
		this.mediaType = MediaType.valueOf(mockMvcProperties.getDefaultMediaType());
		this.charset = Charset.forName(mockMvcProperties.getDefaultCharset());
		this.postProcessors = new ArrayList<>();
		this.isSecure = serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled();
		this.isCsrf = !addonsProperties.getResourceserver().getCsrf().equals(Csrf.DISABLE);
	}

	/**
	 * @param  isSecure if true, requests are sent with https instead of http
	 * @return
	 */
	public MockMvcSupport setSecure(boolean isSecure) {
		this.isSecure = isSecure;
		return this;
	}

	/**
	 * @param  isCsrf should MockMvcRequests be issued with CSRF
	 * @return
	 */
	public MockMvcSupport setCsrf(boolean isCsrf) {
		this.isCsrf = isCsrf;
		return this;
	}

	/**
	 * @param  mediaType override configured default media-type
	 * @return
	 */
	public MockMvcSupport setMediaType(MediaType mediaType) {
		this.mediaType = mediaType;
		return this;
	}

	/**
	 * @param  charset override configured default charset
	 * @return
	 */
	public MockMvcSupport setCharset(Charset charset) {
		this.charset = charset;
		return this;
	}

	/**
	 * Factory for a generic {@link org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder MockHttpServletRequestBuilder} with relevant
	 * "Accept" and "Content-Type" headers. You might prefer to use {@link #getRequestBuilder(MediaType, String, Object...) getRequestBuilder} or alike which go
	 * further with request pre-configuration or even {@link #get(MediaType, String, Object...) get}, {@link #post(Object, String, Object...)} and so on which
	 * issue simple requests in one step.
	 *
	 * @param  accept      should be non-empty when issuing response with body (GET, POST, OPTION), none otherwise
	 * @param  charset     char-set to be used for serialized payloads
	 * @param  method      whatever HTTP verb you need
	 * @param  urlTemplate end-point to be requested
	 * @param  uriVars     end-point template placeholders values
	 * @return             a request builder with minimal info you can tweak further: add headers, cookies, etc.
	 */
	public
			MockHttpServletRequestBuilder
			requestBuilder(Optional<MediaType> accept, Optional<Charset> charset, HttpMethod method, String urlTemplate, Object... uriVars) {
		final var builder = request(method, urlTemplate, uriVars);
		accept.ifPresent(builder::accept);
		charset.ifPresent(c -> builder.characterEncoding(c.toString()));
		builder.secure(isSecure);
		if (isCsrf) {
			builder.with(csrf());
		}
		return builder;
	}

	/**
	 * To be called with fully configured request builder (wraps MockMvc
	 * {@link org.springframework.test.web.servlet.MockMvc#perform(org.springframework.test.web.servlet.RequestBuilder) perform}).
	 *
	 * @param  requestBuilder fully configured request
	 * @return                API answer to be tested
	 */
	public ResultActions perform(MockHttpServletRequestBuilder requestBuilder) {
		postProcessors.forEach(requestBuilder::with);
		try {
			return mockMvc.perform(requestBuilder);
		} catch (final Exception e) {
			throw new MockMvcPerformException(e);
		}
	}

	/* GET */
	/**
	 * Factory providing with a request builder to issue a GET request (with Accept header).
	 *
	 * @param  accept      determines request Accept header (and response body format)
	 * @param  urlTemplate API end-point to call
	 * @param  uriVars     values to feed URL template placeholders
	 * @return             a request builder to be further configured (additional headers, cookies, etc.)
	 */
	public MockHttpServletRequestBuilder getRequestBuilder(MediaType accept, String urlTemplate, Object... uriVars) {
		return requestBuilder(Optional.of(accept), Optional.empty(), HttpMethod.GET, urlTemplate, uriVars);
	}

	/**
	 * Factory providing with a request builder to issue a GET request (with Accept header defaulted to what this helper is constructed with).
	 *
	 * @param  urlTemplate API end-point to call
	 * @param  uriVars     values to feed URL template placeholders
	 * @return             a request builder to be further configured (additional headers, cookies, etc.)
	 */
	public MockHttpServletRequestBuilder getRequestBuilder(String urlTemplate, Object... uriVars) {
		return getRequestBuilder(mediaType, urlTemplate, uriVars);
	}

	/**
	 * Shortcut to issue a GET request with minimal headers and submit it.
	 *
	 * @param  accept      determines request Accept header (and response body format)
	 * @param  urlTemplate API endpoint to be requested
	 * @param  uriVars     values to replace endpoint placeholders with
	 * @return             API response to test
	 */
	public ResultActions get(MediaType accept, String urlTemplate, Object... uriVars) {
		return perform(getRequestBuilder(accept, urlTemplate, uriVars));
	}

	/**
	 * Shortcut to create a builder for a GET request with minimal headers and submit it (Accept header defaulted to what this helper was constructed with).
	 *
	 * @param  urlTemplate API endpoint to be requested
	 * @param  uriVars     values to replace endpoint placeholders with
	 * @return             API response to test
	 */
	public ResultActions get(String urlTemplate, Object... uriVars) {
		return perform(getRequestBuilder(urlTemplate, uriVars));
	}

	/* POST */
	/**
	 * Factory for a POST request builder containing a body set to payload serialized in given media type (with adequate Content-type header).
	 *
	 * @param  payload     to be serialized as body in contentType format
	 * @param  contentType format to be used for payload serialization
	 * @param  charset     char-set for request and response
	 * @param  accept      how should the response body be serialized (if any)
	 * @param  urlTemplate API end-point to be requested
	 * @param  uriVars     values to replace end-point placeholders with
	 * @param  <T>         payload type
	 * @return             Request builder to further configure (cookies, additional headers, etc.)
	 */
	public <
			T>
			MockHttpServletRequestBuilder
			postRequestBuilder(T payload, MediaType contentType, Charset charset, MediaType accept, String urlTemplate, Object... uriVars) {
		return feed(requestBuilder(Optional.of(accept), Optional.of(charset), HttpMethod.POST, urlTemplate, uriVars), payload, contentType, charset);
	}

	/**
	 * Factory for a POST request builder containing a body set to payload serialized in given media type (with adequate Content-type header).
	 *
	 * @param  payload     to be serialized as body in contentType format
	 * @param  contentType format to be used for payload serialization
	 * @param  accept      how should the response body be serialized (if any)
	 * @param  urlTemplate API end-point to be requested
	 * @param  uriVars     values to replace end-point placeholders with
	 * @param  <T>         payload type
	 * @return             Request builder to further configure (cookies, additional headers, etc.)
	 */
	public <T> MockHttpServletRequestBuilder postRequestBuilder(T payload, MediaType contentType, MediaType accept, String urlTemplate, Object... uriVars) {
		return postRequestBuilder(payload, contentType, charset, accept, urlTemplate, uriVars);
	}

	/**
	 * Factory for a POST request builder. Body is pre-set to payload. Both Content-type and Accept headers are set to default media-type.
	 *
	 * @param  payload     request body
	 * @param  urlTemplate API end-point
	 * @param  uriVars     values ofr URL template placeholders
	 * @param  <T>         payload type
	 * @return             Request builder to further configure (cookies, additional headers, etc.)
	 */
	public <T> MockHttpServletRequestBuilder postRequestBuilder(T payload, String urlTemplate, Object... uriVars) {
		return postRequestBuilder(payload, mediaType, charset, mediaType, urlTemplate, uriVars);
	}

	/**
	 * Shortcut to issue a POST request with provided payload as body, using given media-type for serialization (and Content-type header).
	 *
	 * @param  payload     POST request body
	 * @param  contentType media type used to serialize payload and set Content-type header
	 * @param  accept      media-type to be set as Accept header (and response serialization)
	 * @param  charset     char-set for request and response
	 * @param  urlTemplate API end-point to be called
	 * @param  uriVars     values ofr URL template placeholders
	 * @param  <T>         payload type
	 * @return             API response to test
	 */
	public <T> ResultActions post(T payload, MediaType contentType, Charset charset, MediaType accept, String urlTemplate, Object... uriVars) {
		return perform(postRequestBuilder(payload, contentType, charset, accept, urlTemplate, uriVars));
	}

	/**
	 * Shortcut to issue a POST request with provided payload as body, using given media-type for serialization (and Content-type header).
	 *
	 * @param  payload     POST request body
	 * @param  contentType media type used to serialize payload and set Content-type header
	 * @param  accept      media-type to be set as Accept header (and response serialization)
	 * @param  urlTemplate API end-point to be called
	 * @param  uriVars     values ofr URL template placeholders
	 * @param  <T>         payload type
	 * @return             API response to test
	 */
	public <T> ResultActions post(T payload, MediaType contentType, MediaType accept, String urlTemplate, Object... uriVars) {
		return perform(postRequestBuilder(payload, contentType, accept, urlTemplate, uriVars));
	}

	/**
	 * Shortcut to issue a POST request with provided payload as body, using default media-type for serialization (and Content-type header).
	 *
	 * @param  payload     POST request body
	 * @param  urlTemplate API end-point to be called
	 * @param  uriVars     values ofr URL template placeholders
	 * @param  <T>         payload type
	 * @return             API response to test
	 */
	public <T> ResultActions post(T payload, String urlTemplate, Object... uriVars) {
		return perform(postRequestBuilder(payload, urlTemplate, uriVars));
	}

	/* PUT */
	/**
	 * Factory for a POST request builder containing a body.
	 *
	 * @param  payload     to be serialized as body in contentType format
	 * @param  contentType format to be used for payload serialization
	 * @param  charset     char-set for request
	 * @param  urlTemplate API end-point to be requested
	 * @param  uriVars     values to replace end-point placeholders with
	 * @param  <T>         payload type
	 * @return             Request builder to further configure (cookies, additional headers, etc.)
	 */
	public <T> MockHttpServletRequestBuilder putRequestBuilder(T payload, MediaType contentType, Charset charset, String urlTemplate, Object... uriVars) {
		return feed(requestBuilder(Optional.empty(), Optional.of(charset), HttpMethod.PUT, urlTemplate, uriVars), payload, contentType, charset);
	}

	/**
	 * Factory for a POST request builder containing a body.
	 *
	 * @param  payload     to be serialized as body in contentType format
	 * @param  contentType format to be used for payload serialization
	 * @param  urlTemplate API end-point to be requested
	 * @param  uriVars     values to replace end-point placeholders with
	 * @param  <T>         payload type
	 * @return             Request builder to further configure (cookies, additional headers, etc.)
	 */
	public <T> MockHttpServletRequestBuilder putRequestBuilder(T payload, MediaType contentType, String urlTemplate, Object... uriVars) {
		return putRequestBuilder(payload, contentType, charset, urlTemplate, uriVars);
	}

	/**
	 * Factory for a POST request builder containing a body. Default media-type is used for payload serialization (and Content-type header).
	 *
	 * @param  payload     to be serialized as body in contentType format
	 * @param  urlTemplate API end-point to be requested
	 * @param  uriVars     values to replace end-point placeholders with
	 * @param  <T>         payload type
	 * @return             Request builder to further configure (cookies, additional headers, etc.)
	 */
	public <T> MockHttpServletRequestBuilder putRequestBuilder(T payload, String urlTemplate, Object... uriVars) {
		return putRequestBuilder(payload, mediaType, charset, urlTemplate, uriVars);
	}

	/**
	 * Shortcut to issue a PUT request.
	 *
	 * @param  payload     request body
	 * @param  contentType payload serialization media-type
	 * @param  charset     char-set for request and response
	 * @param  urlTemplate API end-point to request
	 * @param  uriVars     values to be used in end-point URL placehoders
	 * @param  <T>         payload type
	 * @return             API response to be tested
	 */
	public <T> ResultActions put(T payload, MediaType contentType, String charset, String urlTemplate, Object... uriVars) {
		return perform(putRequestBuilder(payload, contentType, charset, urlTemplate, uriVars));
	}

	/**
	 * Shortcut to issue a PUT request.
	 *
	 * @param  payload     request body
	 * @param  contentType payload serialization media-type
	 * @param  urlTemplate API end-point to request
	 * @param  uriVars     values to be used in end-point URL placehoders
	 * @param  <T>         payload type
	 * @return             API response to be tested
	 */
	public <T> ResultActions put(T payload, MediaType contentType, String urlTemplate, Object... uriVars) {
		return perform(putRequestBuilder(payload, contentType, urlTemplate, uriVars));
	}

	/**
	 * Shortcut to issue a PUT request (with default media-type as Content-type).
	 *
	 * @param  payload     request body
	 * @param  urlTemplate API end-point to request
	 * @param  uriVars     values to be used in end-point URL placehoders
	 * @param  <T>         payload type
	 * @return             API response to be tested
	 */
	public <T> ResultActions put(T payload, String urlTemplate, Object... uriVars) {
		return perform(putRequestBuilder(payload, urlTemplate, uriVars));
	}

	/* PATCH */
	/**
	 * Factory for a patch request builder (with Content-type already set).
	 *
	 * @param  payload     request body
	 * @param  charset     char-set to be used for serialized payloads
	 * @param  contentType payload serialization format
	 * @param  urlTemplate API end-point
	 * @param  uriVars     values for end-point placeholders
	 * @param  <T>         payload type
	 * @return             request builder to further configure (additional headers, cookies, etc.)
	 */
	public <T> MockHttpServletRequestBuilder patchRequestBuilder(T payload, MediaType contentType, Charset charset, String urlTemplate, Object... uriVars) {
		return feed(requestBuilder(Optional.empty(), Optional.of(charset), HttpMethod.PATCH, urlTemplate, uriVars), payload, contentType, charset);
	}

	/**
	 * Factory for a patch request builder (with Content-type already set).
	 *
	 * @param  payload     request body
	 * @param  contentType payload serialization format
	 * @param  urlTemplate API end-point
	 * @param  uriVars     values for end-point placeholders
	 * @param  <T>         payload type
	 * @return             request builder to further configure (additional headers, cookies, etc.)
	 */
	public <T> MockHttpServletRequestBuilder patchRequestBuilder(T payload, MediaType contentType, String urlTemplate, Object... uriVars) {
		return patchRequestBuilder(payload, contentType, charset, urlTemplate, uriVars);
	}

	/**
	 * Factory for a patch request builder (with Content-type set to default media-type).
	 *
	 * @param  payload     request body
	 * @param  urlTemplate API end-point
	 * @param  uriVars     values for end-point placeholders
	 * @param  <T>         payload type
	 * @return             request builder to further configure (additional headers, cookies, etc.)
	 */
	public <T> MockHttpServletRequestBuilder patchRequestBuilder(T payload, String urlTemplate, Object... uriVars) {
		return patchRequestBuilder(payload, mediaType, charset, urlTemplate, uriVars);
	}

	/**
	 * Shortcut to issue a patch request with Content-type header and a body.
	 *
	 * @param  payload     request body
	 * @param  contentType to be used for payload serialization
	 * @param  charset     to be used for payload serialization
	 * @param  urlTemplate end-point URL
	 * @param  uriVars     values for end-point URL placeholders
	 * @param  <T>         payload type
	 * @return             API response to be tested
	 */
	public <T> ResultActions patch(T payload, MediaType contentType, Charset charset, String urlTemplate, Object... uriVars) {
		return perform(patchRequestBuilder(payload, contentType, charset, urlTemplate, uriVars));
	}

	/**
	 * Shortcut to issue a patch request with Content-type header and a body.
	 *
	 * @param  payload     request body
	 * @param  contentType to be used for payload serialization
	 * @param  urlTemplate end-point URL
	 * @param  uriVars     values for end-point URL placeholders
	 * @param  <T>         payload type
	 * @return             API response to be tested
	 */
	public <T> ResultActions patch(T payload, MediaType contentType, String urlTemplate, Object... uriVars) {
		return perform(patchRequestBuilder(payload, contentType, urlTemplate, uriVars));
	}

	/**
	 * Shortcut to issue a patch request with Content-type header and a body (using default media-type).
	 *
	 * @param  payload     request body
	 * @param  urlTemplate end-point URL
	 * @param  uriVars     values for end-point URL placeholders
	 * @param  <T>         payload type
	 * @return             API response to be tested
	 */
	public <T> ResultActions patch(T payload, String urlTemplate, Object... uriVars) {
		return perform(patchRequestBuilder(payload, urlTemplate, uriVars));
	}

	/* DELETE */
	/**
	 * Factory for a DELETE request builder.
	 *
	 * @param  urlTemplate API end-point
	 * @param  uriVars     values for end-point URL placeholders
	 * @return             request builder to further configure (additional headers, cookies, etc.)
	 */
	public MockHttpServletRequestBuilder deleteRequestBuilder(String urlTemplate, Object... uriVars) {
		return requestBuilder(Optional.empty(), Optional.empty(), HttpMethod.DELETE, urlTemplate, uriVars);
	}

	/**
	 * Shortcut to issue a DELETE request (no header)
	 *
	 * @param  urlTemplate API end-point
	 * @param  uriVars     values for end-point URL placeholders
	 * @return             API response to be tested
	 */
	public ResultActions delete(String urlTemplate, Object... uriVars) {
		return perform(deleteRequestBuilder(urlTemplate, uriVars));
	}

	/* HEAD */
	/**
	 * Factory for a HEAD request builder.
	 *
	 * @param  urlTemplate API end-point
	 * @param  uriVars     values for end-point URL placeholders
	 * @return             request builder to further configure (additional headers, cookies, etc.)
	 */
	public MockHttpServletRequestBuilder headRequestBuilder(String urlTemplate, Object... uriVars) {
		return requestBuilder(Optional.empty(), Optional.empty(), HttpMethod.HEAD, urlTemplate, uriVars);
	}

	/**
	 * Shortcut to issue a HEAD request (no header)
	 *
	 * @param  urlTemplate API end-point
	 * @param  uriVars     values for end-point URL placeholders
	 * @return             API response to be tested
	 */
	public ResultActions head(String urlTemplate, Object... uriVars) {
		return perform(headRequestBuilder(urlTemplate, uriVars));
	}

	/* OPTION */
	/**
	 * Factory for an OPTION request initialized with an Accept header.
	 *
	 * @param  accept      response body media-type
	 * @param  urlTemplate API end-point
	 * @param  uriVars     values for end-point URL placeholders
	 * @return             request builder to be further configured (additional headers, cookies, etc.)
	 */
	public MockHttpServletRequestBuilder optionRequestBuilder(MediaType accept, String urlTemplate, Object... uriVars) {
		return requestBuilder(Optional.of(accept), Optional.empty(), HttpMethod.OPTIONS, urlTemplate, uriVars);
	}

	/**
	 * Factory for an OPTION request initialized with an Accept header set to default media-type.
	 *
	 * @param  urlTemplate API end-point
	 * @param  uriVars     values for end-point URL placeholders
	 * @return             request builder to be further configured (additional headers, cookies, etc.)
	 */
	public MockHttpServletRequestBuilder optionRequestBuilder(String urlTemplate, Object... uriVars) {
		return optionRequestBuilder(mediaType, urlTemplate, uriVars);
	}

	/**
	 * Shortcut to issue an OPTION request with Accept header
	 *
	 * @param  accept      response body media-type
	 * @param  urlTemplate API end-point
	 * @param  uriVars     values for end-point URL placeholders
	 * @return             API response to be further configured
	 */
	public ResultActions option(MediaType accept, String urlTemplate, Object... uriVars) {
		return perform(optionRequestBuilder(accept, urlTemplate, uriVars));
	}

	/**
	 * Shortcut to issue an OPTION request with default media-type as Accept header
	 *
	 * @param  urlTemplate API end-point
	 * @param  uriVars     values for end-point URL placeholders
	 * @return             API response to be further configured
	 */
	public ResultActions option(String urlTemplate, Object... uriVars) {
		return perform(optionRequestBuilder(urlTemplate, uriVars));
	}

	/**
	 * Adds serialized payload to request content. Rather low-level, consider using this class
	 * {@link org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder MockHttpServletRequestBuilder} factories instead (getRequestBuilder,
	 * postRequestBuilder, etc.)
	 *
	 * @param  request   builder you want to set body to
	 * @param  payload   object to be serialized as body
	 * @param  mediaType what format you want payload to be serialized to (corresponding HttpMessageConverter must be registered)
	 * @param  charset   char-set to be used for payload serialization
	 * @param  <T>       payload type
	 * @return           the request with provided payload as content
	 */
	public <T> MockHttpServletRequestBuilder feed(MockHttpServletRequestBuilder request, T payload, MediaType mediaType, Charset charset) {
		if (payload == null) {
			return request;
		}

		final var msg = conv.outputMessage(payload, new MediaType(mediaType, charset));
		return request.headers(msg.headers).content(msg.out.toByteArray());
	}

	public DispatcherServlet getDispatcherServlet() {
		return mockMvc.getDispatcherServlet();
	}

	/**
	 * @param  postProcessor request post-processor to be added to the list of those applied before request is performed
	 * @return               this {@link MockMvcSupport}
	 */
	public MockMvcSupport with(RequestPostProcessor postProcessor) {
		Assert.notNull(postProcessor, "postProcessor is required");
		this.postProcessors.add(postProcessor);
		return this;
	}

}