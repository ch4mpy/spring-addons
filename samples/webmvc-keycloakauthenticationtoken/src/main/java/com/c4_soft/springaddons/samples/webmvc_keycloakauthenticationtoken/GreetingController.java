/*
 * Copyright 2020 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may
 * obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */
package com.c4_soft.springaddons.samples.webmvc_keycloakauthenticationtoken;

import java.security.Principal;

import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingController {
	private final MessageService messageService;

	@Autowired
	public GreetingController(MessageService messageService) {
		this.messageService = messageService;
	}

	@GetMapping("/greet")
	public String greet(KeycloakAuthenticationToken auth) {
		return messageService.greet(auth);
	}

	@GetMapping("/authentication")
	public String greetAuthentication(Authentication auth) {
		return String.format("Hello %s", auth.getName());
	}

	@GetMapping("/principal")
	public String greetPincipal(@AuthenticationPrincipal Principal principal) {
		return String.format("Hello %s", principal.getName());
	}

	@GetMapping("/secured-method")
	@PreAuthorize("hasAuthority('AUTHORIZED_PERSONNEL')")
	public String securedMethod() {
		return "secret method";
	}
}