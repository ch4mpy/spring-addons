/*
 * Copyright 2019 Jérôme Wacongne
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

package com.c4_soft.springaddons.samples.webmvc_oidcauthentication;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import com.c4_soft.springaddons.security.oauth2.oidc.OidcAuthentication;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcToken;

@Service
public class MessageService {

	@PreAuthorize("hasRole('AUTHORIZED_PERSONNEL')")
	public String getSecret() {
		return "Secret message";
	}

	@PreAuthorize("authenticated")
	public String greet(OidcAuthentication<OidcToken> who) {
		return String
				.format(
						"Hello %s! You are granted with %s.",
						who.getToken().getPreferredUsername(),
						who.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
	}

}