package com.c4_soft.springaddons.security.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Claim-sets and authentications end up in HTTP sessions, which are serialized by Spring Session,
 * by servlet containers persisting sessions, or in clustered sessions.
 */
class ClaimSetSerializationTest {
  private static final Map<String, Object> CLAIMS =
      Map.of("iss", "https://op", "sub", "ch4mp", "preferred_username", "Tonton Pirate", "exp",
          1_900_000_000L, "roles", List.of("NICE", "AUTHOR"));

  @Test
  void givenUnmodifiableClaimSet_whenSerializedAndDeserialized_thenClaimsArePreserved()
      throws Exception {
    final var restored = roundTrip(new UnmodifiableClaimSet(CLAIMS));

    assertThat(restored).containsExactlyInAnyOrderEntriesOf(CLAIMS);
  }

  @Test
  void givenModifiableClaimSet_whenSerializedAndDeserialized_thenClaimsArePreserved()
      throws Exception {
    final var restored = roundTrip(new ModifiableClaimSet(CLAIMS));

    assertThat(restored).containsExactlyInAnyOrderEntriesOf(CLAIMS);
  }

  @Test
  void givenOpenidToken_whenSerializedAndDeserialized_thenClaimsUsernameAndTokenValueArePreserved()
      throws Exception {
    final var restored = roundTrip(new OpenidToken(CLAIMS, "$.preferred_username", "a.b.c"));

    assertThat(restored).containsExactlyInAnyOrderEntriesOf(CLAIMS);
    assertThat(restored.getName()).isEqualTo("Tonton Pirate");
    assertThat(restored.getTokenValue()).isEqualTo("a.b.c");
    assertThat(restored.getExpiresAt()).isEqualTo(java.time.Instant.ofEpochSecond(1_900_000_000L));
  }

  @Test
  void givenOAuthentication_whenSerializedAndDeserialized_thenPrincipalAndAuthoritiesArePreserved()
      throws Exception {
    final var authentication = new OAuthentication<>(new OpenidToken(CLAIMS, "sub", "a.b.c"),
        List.of(new SimpleGrantedAuthority("NICE")));

    final var restored = roundTrip(authentication);

    assertThat(restored.getName()).isEqualTo("ch4mp");
    assertThat(restored.getPrincipal()).containsExactlyInAnyOrderEntriesOf(CLAIMS);
    assertThat(restored.getBearerHeader()).isEqualTo("Bearer a.b.c");
    assertThat(restored.getAuthorities()).containsExactly(new SimpleGrantedAuthority("NICE"));
    assertThat(restored.isAuthenticated()).isTrue();
    assertThat(restored).isEqualTo(authentication);
  }

  @SuppressWarnings("unchecked")
  private static <T extends Serializable> T roundTrip(T original)
      throws IOException, ClassNotFoundException {
    final var bytes = new ByteArrayOutputStream();
    try (var out = new ObjectOutputStream(bytes)) {
      out.writeObject(original);
    }
    try (var in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
      return (T) in.readObject();
    }
  }
}
