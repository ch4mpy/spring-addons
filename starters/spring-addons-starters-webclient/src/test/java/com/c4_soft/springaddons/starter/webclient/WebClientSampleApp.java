package com.c4_soft.springaddons.starter.webclient;

import java.net.MalformedURLException;
import java.net.URL;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@SpringBootApplication
public class WebClientSampleApp {
	public static void main(String[] args) {
		new SpringApplicationBuilder(WebClientSampleApp.class).web(WebApplicationType.REACTIVE).run(args);
	}

	@RestController
	@RequestMapping("/sample")
	@RequiredArgsConstructor
	public static class SampleController {
		private final C4WebClientBuilderFactoryService webClientBuilderFactory;

		@GetMapping("/delegating")
		public Mono<String> calling() throws MalformedURLException {
			return webClientBuilderFactory.get(new URL("http://localhost:8080")).build().get().uri("/sample/delegate").retrieve().bodyToMono(String.class);
		}

		@GetMapping("/delegate")
		public Mono<String> remote() {
			return Mono.just("Hello!");
		}
	}
}
