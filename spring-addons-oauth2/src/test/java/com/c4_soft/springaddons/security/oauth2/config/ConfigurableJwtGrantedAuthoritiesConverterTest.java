package com.c4_soft.springaddons.security.oauth2.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;

import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties.Case;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties.IssuerProperties;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;

public class ConfigurableJwtGrantedAuthoritiesConverterTest {

	@Test
	public void test() throws MalformedURLException {
		final var issuer = new URL("https://authorisation-server");

		final var client1Roles = new JSONArray();
		client1Roles.addAll(List.of("R11", "R12"));

		final var client2Roles = new JSONArray();
		client2Roles.addAll(List.of("R21", "R22"));

		final var client3Roles = new JSONArray();
		client3Roles.addAll(List.of("R31", "R32"));

		final var realmRoles = new JSONArray();
		realmRoles.addAll(List.of("r1", "r2"));

		// @formatter:off
		final var claims = new JSONObject(Map.of(
				JwtClaimNames.ISS, issuer,
				"resource_access", new JSONObject(Map.of(
						"client1", new JSONObject(Map.of("roles", client1Roles)),
						"client2", new JSONObject(Map.of("roles", client2Roles)),
						"client3", new JSONObject(Map.of("roles", client3Roles)))),
				"realm_access", new JSONObject(Map.of("roles", realmRoles))));
		// @formatter:on

		final var now = Instant.now();
		final var jwt = new Jwt("a.b.C", now, Instant.ofEpochSecond(now.getEpochSecond() + 3600), Map.of("machin", "truc"), claims);

		final var issuerProperties = new IssuerProperties();
		issuerProperties.setLocation(issuer);

		final var properties = new SpringAddonsSecurityProperties();
		properties.setIssuers(new IssuerProperties[] { issuerProperties });

		final var converter = new ConfigurableClaimSet2AuthoritiesConverter<>(properties);
		final var claimSet = new OpenidClaimSet(jwt.getClaims());

		// Assert mapping with default properties
		assertThat(converter.convert(claimSet).stream().map(GrantedAuthority::getAuthority).toList()).containsExactlyInAnyOrder("r1", "r2");

		// Assert with prefix & uppercase
		issuerProperties.getAuthorities().setClaims(new String[] { "realm_access.roles", "resource_access.client1.roles", "resource_access.client3.roles" });
		issuerProperties.getAuthorities().setPrefix("CHOSE_");
		issuerProperties.getAuthorities().setCaze(Case.UPPER);

		assertThat(converter.convert(claimSet).stream().map(GrantedAuthority::getAuthority).toList())
				.containsExactlyInAnyOrder("CHOSE_R11", "CHOSE_R12", "CHOSE_R31", "CHOSE_R32", "CHOSE_R1", "CHOSE_R2");

		// Assert lowercase (without prefix)
		issuerProperties.getAuthorities().setPrefix("");
		issuerProperties.getAuthorities().setCaze(Case.LOWER);

		assertThat(converter.convert(claimSet).stream().map(GrantedAuthority::getAuthority).toList())
				.containsExactlyInAnyOrder("r11", "r12", "r31", "r32", "r1", "r2");

	}

}
