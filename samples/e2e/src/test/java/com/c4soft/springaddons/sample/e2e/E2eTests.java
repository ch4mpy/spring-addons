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
package com.c4soft.springaddons.sample.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.List;
import java.util.regex.Pattern;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.c4soft.springaddons.sample.e2e.dto.TokenResponse;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = E2eTests.Conf.class, initializers = ConfigFileApplicationContextInitializer.class)
public class E2eTests {
	@Autowired
	@Qualifier("authorizationServer")
	ActuatorApp authorizationServer;

	@Autowired
	@Qualifier("resourceServer")
	ActuatorApp resourceServer;

	TestRestTemplate resourceServerClient = new TestRestTemplate();

	@Test
	public void testJwtWithEmbeddedAuthorities() throws Exception {
		authorizationServer.start("jwt");
		resourceServer.start(List.of("jwt"), List.of("--showcase.authorizationServer=" + authorizationServer.getBaseUri()));

		final HttpHeaders adminHeaders = oauth2Headers("admin");
		final HttpHeaders jpaHeaders = oauth2Headers("jpa");
		ResponseEntity<String> greetingResponse;

		assertThat(adminHeaders.get("Authorization").get(0)).matches(Pattern.compile("Bearer ([\\w-_]+)\\.([\\w-_]+)\\.([\\w-_]+)"));

		greetingResponse = resourceServerClient
				.exchange(resourceServer.getBaseUri() + "greeting", HttpMethod.GET, new HttpEntity<>(adminHeaders), String.class);
		assertThat(greetingResponse.getBody()).isEqualTo("Hello, admin!");

		greetingResponse = resourceServerClient
				.exchange(resourceServer.getBaseUri() + "greeting", HttpMethod.GET, new HttpEntity<>(jpaHeaders), String.class);
		assertThat(greetingResponse.getBody()).isEqualTo("Hello, jpa!");

		greetingResponse = resourceServerClient
				.exchange(resourceServer.getBaseUri() + "restricted", HttpMethod.GET, new HttpEntity<>(adminHeaders), String.class);
		assertThat(greetingResponse.getBody()).isEqualTo("Welcome to restricted area.");

		greetingResponse = resourceServerClient
				.exchange(resourceServer.getBaseUri() + "restricted", HttpMethod.GET, new HttpEntity<>(jpaHeaders), String.class);
		assertThat(greetingResponse.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
	}

	@Test
	public void testJwtWithResourceServerManagedAuthorities() throws Exception {
		authorizationServer.start("jwt");
		resourceServer.start(List.of("jwt", "jpa"), List.of("--showcase.authorizationServer=" + authorizationServer.getBaseUri()));

		final HttpHeaders adminHeaders = oauth2Headers("admin");
		final HttpHeaders jpaHeaders = oauth2Headers("jpa");
		ResponseEntity<String> greetingResponse;

		assertThat(adminHeaders.get("Authorization").get(0)).matches(Pattern.compile("Bearer ([\\w-_]+)\\.([\\w-_]+)\\.([\\w-_]+)"));

		greetingResponse = resourceServerClient
				.exchange(resourceServer.getBaseUri() + "greeting", HttpMethod.GET, new HttpEntity<>(adminHeaders), String.class);
		assertThat(greetingResponse.getBody()).isEqualTo("Hello, admin!");

		greetingResponse = resourceServerClient
				.exchange(resourceServer.getBaseUri() + "greeting", HttpMethod.GET, new HttpEntity<>(jpaHeaders), String.class);
		assertThat(greetingResponse.getBody()).isEqualTo("Hello, jpa!");

		greetingResponse = resourceServerClient
				.exchange(resourceServer.getBaseUri() + "restricted", HttpMethod.GET, new HttpEntity<>(adminHeaders), String.class);
		assertThat(greetingResponse.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

		greetingResponse = resourceServerClient
				.exchange(resourceServer.getBaseUri() + "restricted", HttpMethod.GET, new HttpEntity<>(jpaHeaders), String.class);
		assertThat(greetingResponse.getBody()).isEqualTo("Welcome to restricted area.");
	}

	@Test
	public void testIntrospectedTokenWithEmbeddedAuthorities() throws Exception {
		authorizationServer.start();
		resourceServer.start(List.of(), List.of("--showcase.authorizationServer=" + authorizationServer.getBaseUri()));

		final HttpHeaders adminHeaders = oauth2Headers("admin");
		final HttpHeaders jpaHeaders = oauth2Headers("jpa");
		ResponseEntity<String> greetingResponse;

		assertThat(adminHeaders.get("Authorization").get(0)).doesNotContain(".");

		greetingResponse = resourceServerClient
				.exchange(resourceServer.getBaseUri() + "greeting", HttpMethod.GET, new HttpEntity<>(adminHeaders), String.class);
		assertThat(greetingResponse.getBody()).isEqualTo("Hello, admin!");

		greetingResponse = resourceServerClient
				.exchange(resourceServer.getBaseUri() + "greeting", HttpMethod.GET, new HttpEntity<>(jpaHeaders), String.class);
		assertThat(greetingResponse.getBody()).isEqualTo("Hello, jpa!");

		greetingResponse = resourceServerClient
				.exchange(resourceServer.getBaseUri() + "restricted", HttpMethod.GET, new HttpEntity<>(adminHeaders), String.class);
		assertThat(greetingResponse.getBody()).isEqualTo("Welcome to restricted area.");

		greetingResponse = resourceServerClient
				.exchange(resourceServer.getBaseUri() + "restricted", HttpMethod.GET, new HttpEntity<>(jpaHeaders), String.class);
		assertThat(greetingResponse.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
	}

	@Test
	public void testIntrospectedTokenWithResourceServerManagedAuthorities() throws Exception {
		authorizationServer.start();
		resourceServer.start(List.of("jpa"), List.of("--showcase.authorizationServer=" + authorizationServer.getBaseUri()));

		final HttpHeaders adminHeaders = oauth2Headers("admin");
		final HttpHeaders jpaHeaders = oauth2Headers("jpa");
		ResponseEntity<String> greetingResponse;

		assertThat(adminHeaders.get("Authorization").get(0)).doesNotContain(".");

		greetingResponse = resourceServerClient
				.exchange(resourceServer.getBaseUri() + "greeting", HttpMethod.GET, new HttpEntity<>(adminHeaders), String.class);
		assertThat(greetingResponse.getBody()).isEqualTo("Hello, admin!");

		greetingResponse = resourceServerClient
				.exchange(resourceServer.getBaseUri() + "greeting", HttpMethod.GET, new HttpEntity<>(jpaHeaders), String.class);
		assertThat(greetingResponse.getBody()).isEqualTo("Hello, jpa!");

		greetingResponse = resourceServerClient
				.exchange(resourceServer.getBaseUri() + "restricted", HttpMethod.GET, new HttpEntity<>(adminHeaders), String.class);
		assertThat(greetingResponse.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

		greetingResponse = resourceServerClient
				.exchange(resourceServer.getBaseUri() + "restricted", HttpMethod.GET, new HttpEntity<>(jpaHeaders), String.class);
		assertThat(greetingResponse.getBody()).isEqualTo("Welcome to restricted area.");
	}

	private HttpHeaders oauth2Headers(String subject) {
		HttpHeaders tokenRequestHeaders = new HttpHeaders();
		tokenRequestHeaders.setBasicAuth("user-agent", "secret");
		tokenRequestHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		tokenRequestHeaders.setAccept(List.of(MediaType.APPLICATION_JSON_UTF8));

		MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
		map.add("grant_type", "password");
		map.add("username", subject);
		map.add("password", "password");
		map.add("scope", "showcase");
		HttpEntity<MultiValueMap<String, String>> accessTokenRequest = new HttpEntity<>(map, tokenRequestHeaders);

		final ResponseEntity<TokenResponse> response =
				resourceServerClient.postForEntity(authorizationServer.getBaseUri() + "oauth/token", accessTokenRequest, TokenResponse.class);

		HttpHeaders oauth2Headers = new HttpHeaders();
		oauth2Headers.setBearerAuth(response.getBody().getAccessToken());
		return oauth2Headers;
	}

	@TestConfiguration
	public static class Conf {
		String projectVersion;
		ActuatorApp authorizationServer;
		ActuatorApp resourceServer;

		@Autowired
		public Conf(@Value("${project.version}") String projectVersion) {
			super();
			this.projectVersion = projectVersion;
		}

		@Bean("authorizationServer")
		public ActuatorApp authorizationServer() throws IOException, InterruptedException {
			return ActuatorApp
					.builder("showcase-authorization-server", projectVersion)
					.moduleParentDirectory("..")
					.actuatorClientId("actuator")
					.actuatorClientSecret("secret")
					.build();
		}

		@Bean("resourceServer")
		public ActuatorApp resourceServer() throws IOException, InterruptedException {
			return ActuatorApp
					.builder("showcase-resource-server", projectVersion)
					.moduleParentDirectory("..")
					.actuatorClientId("actuator")
					.actuatorClientSecret("secret")
					.build();
		}
	}
}
