/*
 * Copyright 2019 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
 */

package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class MessageService {
	private final SecretRepo fooRepo;

	@PreAuthorize("hasRole('AUTHORIZED_PERSONNEL')")
	public String getSecret() {
		final var auth = (BearerTokenAuthentication) SecurityContextHolder.getContext().getAuthentication();
		return fooRepo.findSecretByUsername(auth.getTokenAttributes().get(StandardClaimNames.PREFERRED_USERNAME).toString());
	}

	@PreAuthorize("isAuthenticated()")
	public String greet(BearerTokenAuthentication who) {
		return String.format(
				"Hello %s! You are granted with %s.",
				who.getTokenAttributes().get(StandardClaimNames.PREFERRED_USERNAME),
				who.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
	}

}