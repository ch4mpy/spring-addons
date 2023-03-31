package com.c4soft.springaddons.tutorials;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexController {

	@GetMapping("/")
	public String getIndex(Authentication auth, Model model) {
		model.addAttribute("isAuthenticated", auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken));
		return "index";
	}
}
