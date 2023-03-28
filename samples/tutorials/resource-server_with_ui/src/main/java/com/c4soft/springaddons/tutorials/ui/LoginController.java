package com.c4soft.springaddons.tutorials.ui;

import java.net.URISyntaxException;
import java.util.List;
import java.util.stream.StreamSupport;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.view.RedirectView;

@Controller
public class LoginController {
	private final List<ClientRegistration> clientRegistrations;

	public LoginController(InMemoryClientRegistrationRepository clientRegistrationRepo) {
		this.clientRegistrations = StreamSupport.stream(clientRegistrationRepo.spliterator(), false)
				.filter(reg -> AuthorizationGrantType.AUTHORIZATION_CODE.equals(reg.getAuthorizationGrantType())).toList();
	}

	@GetMapping("/login")
	public RedirectView getLogin() throws URISyntaxException {
		if (clientRegistrations.size() == 1) {
			return new RedirectView(loginPath(clientRegistrations.get(0)));
		}
		return new RedirectView("login/opts");
	}

	@GetMapping("/login/opts")
	public String getLoginOpts(Authentication auth, Model model) throws URISyntaxException {
		model.addAttribute("isAuthenticated", auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken));
		model.addAttribute(
				"loginOptions",
				clientRegistrations.stream().map(clientRegistration -> new LoginOptionDto(clientRegistration.getClientName(), loginPath(clientRegistration)))
						.toList());
		return "login";
	}

	static String loginPath(ClientRegistration clientRegistration) {
		return "/oauth2/authorization/%s".formatted(clientRegistration.getRegistrationId());
	}

	static record LoginOptionDto(String name, String loginPath) {
	}
}
