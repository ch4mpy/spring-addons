package com.c4soft.springaddons.tutorials.ui;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.c4_soft.springaddons.rest.SpringAddonsRestClientSupport;

@Configuration
public class RestClientsConfig {

	@Bean
	GreetApi greetApi(SpringAddonsRestClientSupport restSupport) {
		// binds to com.c4-soft.springaddons.rest.client.greet-api properties
		return restSupport.service("greet-api", GreetApi.class);
	}

}
