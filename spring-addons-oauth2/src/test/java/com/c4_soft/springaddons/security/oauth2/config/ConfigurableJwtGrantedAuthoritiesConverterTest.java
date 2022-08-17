package com.c4_soft.springaddons.security.oauth2.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

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
		final URL issuer = new URL("https://authorisation-server");

		final JSONArray client1Roles = new JSONArray();
		client1Roles.addAll(Arrays.asList("R11", "R12"));

		final JSONArray client2Roles = new JSONArray();
		client2Roles.addAll(Arrays.asList("R21", "R22"));

		final JSONArray client3Roles = new JSONArray();
		client3Roles.addAll(Arrays.asList("R31", "R32"));

		final JSONArray realmRoles = new JSONArray();
		realmRoles.addAll(Arrays.asList("r1", "r2"));

		// @formatter:off
		final Map<String, Object> resourceAccess = new HashMap<>();
		final Map<String, Object> client1 = new HashMap<>();
		client1.put("roles", client1Roles);
		final Map<String, Object> client2 = new HashMap<>();
		client2.put("roles", client2Roles);
		final Map<String, Object> client3 = new HashMap<>();
		client3.put("roles", client3Roles);
		resourceAccess.put("client1", new JSONObject(client1));
		resourceAccess.put("client2", new JSONObject(client2));
		resourceAccess.put("client3", new JSONObject(client3));

		final Map<String, Object> realmAccess = new HashMap<>();
		realmAccess.put("roles", realmRoles);

		final Map<String, Object> claims = new HashMap<>();
		claims.put(JwtClaimNames.ISS, issuer);
		claims.put("resource_access", new JSONObject(resourceAccess));
		claims.put("realm_access", new JSONObject(realmAccess));
		// @formatter:on

		final Map<String, Object> privateClaims = new HashMap<>();
		privateClaims.put("machin", "truc");

		final Instant now = Instant.now();
		final Jwt jwt = new Jwt("a.b.C", now, Instant.ofEpochSecond(now.getEpochSecond() + 3600), privateClaims, new JSONObject(claims));

		final IssuerProperties issuerProperties = new IssuerProperties();
		issuerProperties.setLocation(issuer);

		final SpringAddonsSecurityProperties properties = new SpringAddonsSecurityProperties();
		properties.setIssuers(new IssuerProperties[] { issuerProperties });

		final ConfigurableClaimSet2AuthoritiesConverter<OpenidClaimSet> converter = new ConfigurableClaimSet2AuthoritiesConverter<>(properties);
		final OpenidClaimSet claimSet = new OpenidClaimSet(jwt.getClaims());

		// Assert mapping with default properties
		assertThat(converter.convert(claimSet).stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList())).containsExactlyInAnyOrder("r1", "r2");

		// Assert with prefix & uppercase
		issuerProperties.getAuthorities().setClaims(new String[] { "realm_access.roles", "resource_access.client1.roles", "resource_access.client3.roles" });
		issuerProperties.getAuthorities().setPrefix("CHOSE_");
		issuerProperties.getAuthorities().setCaze(Case.UPPER);

		assertThat(converter.convert(claimSet).stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
				.containsExactlyInAnyOrder("CHOSE_R11", "CHOSE_R12", "CHOSE_R31", "CHOSE_R32", "CHOSE_R1", "CHOSE_R2");

		// Assert lowercase (without prefix)
		issuerProperties.getAuthorities().setPrefix("");
		issuerProperties.getAuthorities().setCaze(Case.LOWER);

		assertThat(converter.convert(claimSet).stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
				.containsExactlyInAnyOrder("r11", "r12", "r31", "r32", "r1", "r2");

	}

}
