package com.c4_soft.springaddons.security.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ClaimSetTest {
  private static final Instant EXP = Instant.ofEpochSecond(1_900_000_000L);

  @Test
  void givenNumericDateOfAnyNumberType_whenGetAsInstant_thenSecondsSinceEpoch() {
    final var claims = new ModifiableClaimSet(Map.of("long", 1_900_000_000L, "int",
        1_900_000_000, "double", 1_900_000_000.0, "date", Date.from(EXP), "instant", EXP,
        "iso", EXP.toString()));

    for (final var name : List.of("long", "int", "double", "date", "instant", "iso")) {
      assertThat(claims.getAsInstant(name)).as(name).isEqualTo(EXP);
    }
  }

  @Test
  void givenMissingClaim_whenGetAsInstant_thenNull() {
    assertThat(new ModifiableClaimSet().getAsInstant("exp")).isNull();
  }

  @Test
  void givenUnparsableClaim_whenGetAsInstant_thenUnparsableClaimException() {
    final var claims = new ModifiableClaimSet(Map.of("str", "not a date", "list", List.of(1)));

    assertThatThrownBy(() -> claims.getAsInstant("str"))
        .isInstanceOf(UnparsableClaimException.class);
    assertThatThrownBy(() -> claims.getAsInstant("list"))
        .isInstanceOf(UnparsableClaimException.class);
  }
}
