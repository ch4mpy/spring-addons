/*
 * Copyright 2020 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.c4_soft.springaddons.samples.webmvc.common.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.c4_soft.springaddons.samples.webmvc.common.domain.MessageService;

@RestController
public class GreetingController<T extends Authentication> {
	private final MessageService<T> messageService;

	@Autowired
	public GreetingController(MessageService<T> messageService) {
		this.messageService = messageService;
	}

	@GetMapping("/greet")
	public String greet(T auth) {
		return messageService.greet(auth);
	}

	@GetMapping("/secured-route")
	public String securedRoute() {
		return "secret route";
	}

	@GetMapping("/secured-method")
	@PreAuthorize("hasRole('AUTHORIZED_PERSONNEL')")
	public String securedMethod() {
		return "secret method";
	}
}