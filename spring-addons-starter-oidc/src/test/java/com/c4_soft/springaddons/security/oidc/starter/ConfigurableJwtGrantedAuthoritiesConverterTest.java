package com.c4_soft.springaddons.security.oidc.starter;

import static org.assertj.core.api.Assertions.assertThat;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import com.c4_soft.springaddons.security.oidc.OpenidClaimSet;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties.OpenidProviderProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties.OpenidProviderProperties.SimpleAuthoritiesMappingProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties.OpenidProviderProperties.SimpleAuthoritiesMappingProperties.Case;

public class ConfigurableJwtGrantedAuthoritiesConverterTest {

  @Test
  public void test() throws URISyntaxException {
    final var issuer = new URI("https://authorisation-server");

    final var client1Roles = List.of("R11", "r12");

    final var client2Roles = List.of("R21", "r22");

    final var client3Roles = List.of("R31", "r32");

    final var realmRoles = List.of("r1", "r 2");

    final var scope = "s1 s2";

    // @formatter:off
		final var claims = Map.of(
				JwtClaimNames.ISS, issuer,
				"resource_access", Map.of(
						"client1", Map.of("roles", client1Roles),
						"client2", Map.of("roles", client2Roles.stream().collect(Collectors.joining(", "))),
						"client3", Map.of("roles", client3Roles.stream().collect(Collectors.joining(" ")))),
				"realm_access", Map.of("roles", realmRoles),
				"scope", scope);
		// @formatter:on

    final var now = Instant.now();
    final var jwt = new Jwt("a.b.C", now, Instant.ofEpochSecond(now.getEpochSecond() + 3600),
        Map.of("machin", "truc"), claims);

    final var issuerProperties = new OpenidProviderProperties();
    issuerProperties.setIss(issuer);

    final var properties = new SpringAddonsOidcProperties();
    properties.setOps(List.of(issuerProperties));

    final var converter = new ConfigurableClaimSetAuthoritiesConverter(
        new ByIssuerOpenidProviderPropertiesResolver(properties));
    final var claimSet = new OpenidClaimSet(jwt.getClaims());

    // Assert mapping with default properties
    assertThat(converter.convert(claimSet).stream().map(GrantedAuthority::getAuthority).toList())
        .isEmpty();

    // Assert with prefix & uppercase
    issuerProperties.setAuthorities(List.of(
        simpleAuthoritiesMappingProperties("$.realm_access.roles", "MACHIN_", Case.UNCHANGED),
        simpleAuthoritiesMappingProperties("resource_access.client1.roles", "TRUC_", Case.LOWER),
        simpleAuthoritiesMappingProperties("resource_access.client3.roles", "CHOSE_", Case.UPPER),
        simpleAuthoritiesMappingProperties("scope", "SCOPE_", Case.UNCHANGED)));

    assertThat(converter.convert(claimSet).stream().map(GrantedAuthority::getAuthority).toList())
        .containsExactlyInAnyOrder("TRUC_r11", "TRUC_r12", "CHOSE_R31", "CHOSE_R32", "MACHIN_r1",
            "MACHIN_r 2", "SCOPE_s1", "SCOPE_s2");
  }

  private static SimpleAuthoritiesMappingProperties simpleAuthoritiesMappingProperties(
      String jsonPath, String prefix, Case caseTransformation) {
    final var props = new SimpleAuthoritiesMappingProperties();
    props.setCaze(caseTransformation);
    props.setPath(jsonPath);
    props.setPrefix(prefix);
    return props;
  }

}
