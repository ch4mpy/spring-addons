package com.c4_soft.springaddons.security.oauth2.test.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.core.annotation.AliasFor;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;

/**
 * <p>
 * Populates the test security context with an {@link OAuth2AuthenticationToken} instance with a
 * {@link DefaultOAuth2User} as principal.
 * </p>
 * <p>
 * Only the annotation properties are used to build the authentication Instance. <b>Neither
 * {@link OAuth2UserService} nor {@link GrantedAuthoritiesMapper} are called.</b>
 * </p>
 * Usage to define just authorities:
 * 
 * <pre>
 * &#64;WithOAuth2Login({"BIDULE", "CHOSE"})
 * </pre>
 * 
 * Advanced usage to set any claims, including private ones:
 * 
 * <pre>
 * &#64;WithOAuth2Login(
 *   authorities = {"NICE"},
 *   nameAttributeKey = StandardClaimNames.PREFERRED_USERNAME,
 *   claims = &#64;OpenIdClaims(
 *     preferredUsername = "tonton-pirate",
 *     email = "tonton@c4-soft.com",
 *     otherClaims =  &#64;Claims(
 *       stringClaims = { &#64;StringClaim(name = "machin", value = "truc") })))
 * </pre>
 * 
 * @author ch4mp&#64;c4-soft.com
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithOAuth2Login.OAuth2AuthenticationTokenFactory.class)
public @interface WithOAuth2Login {

  @AliasFor("authorities")
  String[] value() default {};

  @AliasFor("value")
  String[] authorities() default {};

  OpenIdClaims claims() default @OpenIdClaims();

  String tokenString() default "machin.truc.chose";

  String authorizedClientRegistrationId() default "bidule";

  /**
   * @return the key used to access the user's &quot;name&quot; from claims. This takes precedence
   *         over OpenIdClaims::usernameClaim if both are defined
   */
  String nameAttributeKey() default JwtClaimNames.SUB;

  @AliasFor(annotation = WithSecurityContext.class)
  TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

  public static final class OAuth2AuthenticationTokenFactory
      extends AbstractAnnotatedAuthenticationBuilder<WithOAuth2Login, OAuth2AuthenticationToken> {
    public OAuth2AuthenticationTokenFactory() {
      super(WithOAuth2Login.class);
    }

    @Override
    public OAuth2AuthenticationToken authentication(WithOAuth2Login annotation) {
      final var token =
          super.claims(annotation.claims()).usernameClaim(annotation.nameAttributeKey()).build();
      final var authorities = super.authorities(annotation.authorities(), annotation.value());
      final var principal =
          new DefaultOAuth2User(authorities, token, annotation.nameAttributeKey());

      return new OAuth2AuthenticationToken(principal, authorities,
          annotation.authorizedClientRegistrationId());
    }
  }
}
