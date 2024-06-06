package com.c4soft.springaddons.tutorials.ui;

import org.springframework.http.MediaType;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;

@HttpExchange(accept = MediaType.APPLICATION_JSON_VALUE)
public interface GreetApi {
	@GetExchange(url = "/greet")
	String getGreeting();
}