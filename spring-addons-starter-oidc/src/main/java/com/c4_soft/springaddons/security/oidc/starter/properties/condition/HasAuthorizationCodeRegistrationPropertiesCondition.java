package com.c4_soft.springaddons.security.oidc.starter.properties.condition;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

/**
 * Matches when at least one of the OAuth2 client registrations declared with
 * {@code spring.security.oauth2.client.registration.*} properties uses the
 * {@code authorization_code} flow.
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public class HasAuthorizationCodeRegistrationPropertiesCondition
    extends HasOAuth2RegistrationWithGrantTypeCondition {

  public HasAuthorizationCodeRegistrationPropertiesCondition() {
    super(AuthorizationGrantType.AUTHORIZATION_CODE);
  }
}
