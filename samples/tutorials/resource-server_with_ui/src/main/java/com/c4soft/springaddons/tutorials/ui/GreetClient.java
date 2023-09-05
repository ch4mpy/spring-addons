package com.c4soft.springaddons.tutorials.ui;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;

@FeignClient(name = "quizzes", url = "${spring.cloud.openfeign.client.api.url}")
public interface GreetClient {
	@GetMapping(value = "/greet")
	String getGreeting();
}