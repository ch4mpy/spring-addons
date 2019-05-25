/*
 * Copyright 2019 Jérôme Wacongne
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
package org.springframework.security.oauth2.server.resource.authentication;

import com.c4soft.oauth2.rfc7662.IntrospectionClaimSet;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class IntrospectionAuthentication extends OAuth2Authentication<IntrospectionClaimSet> {
	private static final long serialVersionUID = -5121824981488824261L;

	public IntrospectionAuthentication(IntrospectionClaimSet claims, PrincipalGrantedAuthoritiesService authoritiesService) {
		super(claims, authoritiesService);
	}

}
