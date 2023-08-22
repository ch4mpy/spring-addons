package com.c4soft.springaddons.samples.bff.users.web;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.micrometer.observation.annotation.Observed;
import io.swagger.v3.oas.annotations.tags.Tag;

@RestController
@RequestMapping(path = "/public", produces = MediaType.APPLICATION_JSON_VALUE)
@Tag(name = "Greetings")
@Observed(name = "PublicController")
public class PublicController {
	@GetMapping("/hello")
	@Tag(name = "get")
	public GreetingDto getHello() {
		return new GreetingDto("Hello Wrold!");
	}
}
