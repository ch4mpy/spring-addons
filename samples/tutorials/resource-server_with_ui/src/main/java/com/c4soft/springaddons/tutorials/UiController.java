package com.c4soft.springaddons.tutorials;

import java.net.URI;
import java.net.URISyntaxException;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
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
	private final ResourceServerWithUiProperties props;

	@GetMapping("/login")
	public String getLogin() throws URISyntaxException {
		// FIXME: generate login links from authorized clients with authorization-code
		return "login";
	}

	@GetMapping("/greet")
	public String getGreeting(Model model, OAuth2AuthenticationToken auth) throws URISyntaxException {
		try {
			final var authorizedClient = authorizedClientService.loadAuthorizedClient(auth.getAuthorizedClientRegistrationId(), auth.getName());
			final var greetApiUri = new URI(props.getApiHost().getProtocol(), props.getApiHost().getAuthority(), "/api/greet", null, null);
			final var response =
					api.get().uri(greetApiUri).attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
							.exchangeToMono(r -> r.toEntity(String.class)).block();
			model.addAttribute("msg", response.getStatusCode().is2xxSuccessful() ? response.getBody() : response.getStatusCode().toString());

		} catch (RestClientException e) {
			final var error = e.getMessage();
			model.addAttribute("msg", error);

		}
		return "greet";
	}
}
