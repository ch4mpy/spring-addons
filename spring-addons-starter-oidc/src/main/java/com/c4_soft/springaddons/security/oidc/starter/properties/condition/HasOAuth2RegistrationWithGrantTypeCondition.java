package com.c4_soft.springaddons.security.oidc.starter.properties.condition;

import java.util.HashMap;
import java.util.Map;
import org.jspecify.annotations.NonNull;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.StringUtils;
import lombok.Data;
import lombok.RequiredArgsConstructor;

/**
 * Matches when at least one of the OAuth2 client registrations declared with
 * {@code spring.security.oauth2.client.registration.*} properties uses the expected
 * {@link AuthorizationGrantType}.
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@RequiredArgsConstructor
public class HasOAuth2RegistrationWithGrantTypeCondition implements Condition {
  private static final String REGISTRATIONS_PREFIX = "spring.security.oauth2.client.registration";

  private final AuthorizationGrantType grantType;

  @Override
  public boolean matches(@NonNull ConditionContext context,
      @NonNull AnnotatedTypeMetadata metadata) {
    return authorizationGrantTypesByRegistrationId(context.getEnvironment())
        .containsValue(grantType);
  }

  /**
   * <p>
   * Reads the {@link AuthorizationGrantType} of each OAuth2 client registration declared with
   * {@code spring.security.oauth2.client.registration.*} properties. This is intended for
   * conditions and bean factory methods which must know which flows are configured before the
   * {@code ClientRegistrationRepository} can be resolved.
   * </p>
   * <p>
   * As Spring Boot does, registrations without an explicit
   * {@code authorization-grant-type} are considered to be using
   * {@link AuthorizationGrantType#AUTHORIZATION_CODE} (this is what
   * {@code CommonOAuth2Provider} defaults to).
   * </p>
   *
   * @param environment the application environment
   * @return the authorization grant type of each registration, by registration ID
   */
  public static Map<String, AuthorizationGrantType> authorizationGrantTypesByRegistrationId(
      Environment environment) {
    final var registrations = Binder.get(environment)
        .bind(REGISTRATIONS_PREFIX, Bindable.mapOf(String.class, RegistrationProperties.class))
        .orElseGet(Map::of);

    final var grantTypes = new HashMap<String, AuthorizationGrantType>(registrations.size());
    registrations.forEach((registrationId, registration) -> grantTypes.put(registrationId,
        StringUtils.hasText(registration.getAuthorizationGrantType())
            ? new AuthorizationGrantType(registration.getAuthorizationGrantType())
            : AuthorizationGrantType.AUTHORIZATION_CODE));

    return grantTypes;
  }

  /**
   * The subset of Spring Boot OAuth2 client registration properties we need. {@code client-id} and
   * {@code provider} are bound only to ensure that registrations without an explicit
   * {@code authorization-grant-type} are not skipped by the {@link Binder}.
   */
  @Data
  public static class RegistrationProperties {
    private String clientId;
    private String provider;
    private String authorizationGrantType;
  }
}
