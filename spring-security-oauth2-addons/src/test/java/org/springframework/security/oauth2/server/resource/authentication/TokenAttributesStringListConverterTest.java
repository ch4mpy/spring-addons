package org.springframework.security.oauth2.server.resource.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.Set;

import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class TokenAttributesStringListConverterTest {
	// Intentional dirty inputs to check cleanup
	private static final Map<String, Object> ATTRIBUTES = Map.of(
			"authorities", Set.of(new SimpleGrantedAuthority("auth1"), new SimpleGrantedAuthority("auth2")),
			"space-separated", "s1  s2 ",
			"array", new String[] { "arr1", null, "", "arr2 "},
			"scope", "s3 s4");

	@Test
	public void allAndOnlyAttributesGivenToConstructorAreScaned() {
		final var converter = new TokenAttributesStringListConverter(Set.of("authorities", "space-separated", "array"), " ");
		assertThat(converter.convert(ATTRIBUTES)).containsExactlyInAnyOrder(
				"auth1",
				"auth2",
				"s1",
				"s2",
				"arr1",
				"arr2");
	}@Test
	public void regexIsUsedToSplitScanedAttributes() {
		final var converter = new TokenAttributesStringListConverter(Set.of("scope"), ",");
		assertThat(converter.convert(Map.of("scope", "s1,s2,,"))).containsExactlyInAnyOrder(
				"s1",
				"s2");
	}

}
