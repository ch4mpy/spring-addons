package com.c4soft.springaddons.tutorials.ui;

import java.io.Serializable;
import java.net.URISyntaxException;

import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class LoginController {
	private final OAuth2ClientProperties clientProps;

	@GetMapping("/login")
	public String getLogin(Model model, Authentication auth) throws URISyntaxException {
		final var loginOptions =
				clientProps.getRegistration().entrySet().stream().filter(e -> "authorization_code".equals(e.getValue().getAuthorizationGrantType()))
						.map(e -> new LoginOptionDto(e.getValue().getProvider(), e.getKey())).toList();

		model.addAttribute("isAuthenticated", auth != null && auth.isAuthenticated());
		model.addAttribute("loginOptions", loginOptions);

		return "login";
	}

	@Data
	@AllArgsConstructor
	static class LoginOptionDto implements Serializable {
		private static final long serialVersionUID = -7598910797375105284L;

		private final String label;
		private final String provider;
	}
}
