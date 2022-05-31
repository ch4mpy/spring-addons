package com.c4_soft.springaddons.security.oauth2.test.webflux;

import static org.mockito.Mockito.mock;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Scope;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.test.web.reactive.server.WebTestClient;

@AutoConfiguration
@Import({ WebTestClientProperties.class })
public class AddonsWebfluxTestConf {

	@Bean
	HttpSecurity httpSecurity() {
		return mock(HttpSecurity.class);
	}

	@Bean
	@Scope("prototype")
	public WebTestClientSupport webTestClientSupport(WebTestClientProperties webTestClientProperties, WebTestClient webTestClient) {
		return new WebTestClientSupport(webTestClientProperties, webTestClient);
	}

}