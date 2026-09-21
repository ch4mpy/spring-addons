package com.c4_soft.springaddons.security.oauth2.test.annotations;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import com.c4_soft.springaddons.security.oauth2.test.Defaults;

class WithOidcLoginTest {

  private final WithOidcLogin.OAuth2AuthenticationTokenFactory factory =
      new WithOidcLogin.OAuth2AuthenticationTokenFactory();

  @Test
  @WithOidcLogin(authorities = {"NICE", "AUTHOR"},
      claims = @OpenIdClaims(preferredUsername = "brice", email = "brice@c4-soft.com"))
  void givenDefaultNameAttributeKey_whenBuildingAuthentication_thenNameIsTheSubClaim()
      throws NoSuchMethodException {
    final var auth = factory.authentication(annotation(
        "givenDefaultNameAttributeKey_whenBuildingAuthentication_thenNameIsTheSubClaim"));

    assertThat(auth.getName()).isEqualTo(Defaults.SUBJECT);
    assertThat(auth.getAuthorities().stream().map(GrantedAuthority::getAuthority))
        .containsExactlyInAnyOrder("NICE", "AUTHOR");
    assertThat(((OidcUser) auth.getPrincipal()).getPreferredUsername()).isEqualTo("brice");
  }

  /**
   * {@code nameAttributeKey} used to be ignored: the {@code DefaultOidcUser} was built without it, so
   * {@code Authentication#getName()} always returned the {@code sub} claim.
   */
  @Test
  @WithOidcLogin(nameAttributeKey = StandardClaimNames.PREFERRED_USERNAME,
      claims = @OpenIdClaims(preferredUsername = "brice"))
  void givenNameAttributeKey_whenBuildingAuthentication_thenNameIsThatClaim()
      throws NoSuchMethodException {
    final var auth = factory
        .authentication(annotation("givenNameAttributeKey_whenBuildingAuthentication_thenNameIsThatClaim"));

    assertThat(auth.getName()).isEqualTo("brice");
    assertThat(((OidcUser) auth.getPrincipal()).getName()).isEqualTo("brice");
  }

  @Test
  @WithOidcLogin(authorizedClientRegistrationId = "keycloak")
  void givenAuthorizedClientRegistrationId_whenBuildingAuthentication_thenItIsSet()
      throws NoSuchMethodException {
    final var auth = factory.authentication(
        annotation("givenAuthorizedClientRegistrationId_whenBuildingAuthentication_thenItIsSet"));

    assertThat(auth.getAuthorizedClientRegistrationId()).isEqualTo("keycloak");
  }

  private WithOidcLogin annotation(String methodName) throws NoSuchMethodException {
    return WithOidcLoginTest.class.getDeclaredMethod(methodName).getAnnotation(WithOidcLogin.class);
  }
}
