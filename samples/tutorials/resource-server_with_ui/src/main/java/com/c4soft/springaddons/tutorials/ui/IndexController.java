package com.c4soft.springaddons.tutorials.ui;

import java.net.URISyntaxException;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.view.RedirectView;

import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class IndexController {
	@GetMapping("/")
	public RedirectView getIndex() throws URISyntaxException {
		return new RedirectView("/ui/");
	}
}
