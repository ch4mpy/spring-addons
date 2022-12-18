package com.c4soft.springaddons.tutorials;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestClientException;
import org.springframework.web.reactive.function.client.WebClient;

import lombok.RequiredArgsConstructor;

@Controller
@RequestMapping("/ui")
@RequiredArgsConstructor
public class UiController {
	private final WebClient api;
	private final OAuth2AuthorizedClientService authorizedClientService;

	@GetMapping("/greet")
	public String getGreeting(Model model, Authentication auth) {
		try {
			final var authorizedClient = authorizedClientService.loadAuthorizedClient("spring-addons-public", auth.getName());
			final var response = api.get().uri("http://localhost:8080/api/greet")
					.attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction
							.oauth2AuthorizedClient(authorizedClient))
					.exchangeToMono(r -> r.toEntity(String.class)).block();
			model.addAttribute("msg", response.getStatusCode().is2xxSuccessful() ? response.getBody() : response.getStatusCode().toString());
			
		} catch (RestClientException e) {
			final var error = e.getMessage();
			model.addAttribute("msg", error);
			
		}
		return "greet";
	}
}
