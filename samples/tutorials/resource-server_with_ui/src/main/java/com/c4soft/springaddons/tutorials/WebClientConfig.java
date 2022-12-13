package com.c4soft.springaddons.tutorials;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebClientConfig {
	/**
	 * By default, WebClient expects reactive OAuth2 configuration. This bridges from ClientRegistrationRepository to ReactiveClientRegistrationRepository
	 * @param clientRegistrationRepository
	 * @param authorizedClientService
	 * @return
	 */
	@Bean
	WebClient webClient(ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientService authorizedClientService) {
		var oauth = new ServletOAuth2AuthorizedClientExchangeFilterFunction(
				new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository,
						authorizedClientService));
		oauth.setDefaultClientRegistrationId("spring-addons-public");
		return WebClient.builder().apply(oauth.oauth2Configuration()).build();
	}

}
