/*
 * Copyright 2020 Jérôme Wacongne.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.c4_soft.springaddons.security.oauth2.test.annotations.keycloak;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessToken.Access;
import org.keycloak.representations.AccessToken.Authorization;
import org.keycloak.representations.idm.authorization.Permission;
import org.springframework.util.StringUtils;

class AccessTokenBuilderHelper {

	public static AccessToken feed(AccessToken token, WithMockKeycloakAuth annotation) {
		IDTokenBuilderHelper.feed(token, annotation.id(), annotation.oidc(), annotation.privateClaims());

		token.setAuthorization(authorization(annotation.accessToken().authorization().permissions()));

		token.setRealmAccess(
				access(
						Stream.concat(
								Stream.of(annotation.accessToken().realmAccess().roles()),
								Stream.of(annotation.authorities())),
						annotation.accessToken().realmAccess().verifyCaller()));

		if (StringUtils.hasLength(annotation.accessToken().certConf().certThumbprint())) {
			final var certConf = new AccessToken.CertConf();
			certConf.setCertThumbprint(annotation.accessToken().certConf().certThumbprint());
			token.setCertConf(certConf);
		}

		token.setResourceAccess(resourceAccess(annotation.accessToken().resourceAccess()));

		token.setAllowedOrigins(Stream.of(annotation.accessToken().allowedOrigins()).collect(Collectors.toSet()));

		token.setTrustedCertificates(
				Stream.of(annotation.accessToken().trustedCertificates()).collect(Collectors.toSet()));

		return token;
	}

	static Authorization authorization(KeycloakPermission... permissions) {
		final var authorization = new Authorization();
		authorization.setPermissions(
				Stream.of(permissions).map(AccessTokenBuilderHelper::permission).collect(Collectors.toList()));
		return authorization;
	}

	static Permission permission(KeycloakPermission annotation) {
		final var scopes = Stream.of(annotation.scopes()).collect(Collectors.toSet());
		final var claims = new HashMap<String, Set<String>>(annotation.claims().length);
		for (var claim : annotation.claims()) {
			var c = claims.containsKey(claim.name()) ? claims.get(claim.name()) : new HashSet<String>();
			c.add(claim.value());
			claims.put(claim.name(), c);
		}
		return new Permission(annotation.rsid(), nullIfEmpty(annotation.rsname()), scopes, claims);
	}

	static Access access(Stream<String> roles, Boolean verifyCaller) {
		final var access = new Access();
		access.roles(roles.collect(Collectors.toSet()));
		access.verifyCaller(verifyCaller);
		return access;
	}

	static Map<String, Access> resourceAccess(KeycloakResourceAccess[] annotations) {
		final var accesses = new HashMap<String, Access>(annotations.length);
		for (var annotation : annotations) {
			accesses.put(
					annotation.resourceId(),
					access(Stream.of(annotation.access().roles()), annotation.access().verifyCaller()));
		}
		return accesses;
	}

	private static String nullIfEmpty(String str) {
		return StringUtils.isEmpty(str) ? null : str;
	}
}
