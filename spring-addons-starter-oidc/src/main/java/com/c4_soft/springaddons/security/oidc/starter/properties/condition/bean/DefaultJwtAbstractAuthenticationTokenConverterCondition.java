package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsOidcResourceServerCondition;
import reactor.core.publisher.Mono;

/**
 * Matches when the default {@code jwtAuthenticationConverter} bean should be created: the resource
 * server auto-configuration is active with JWT decoding, and no bean converting a {@link Jwt} to an
 * {@link AbstractAuthenticationToken} (or to a {@link Mono} of one) is defined, whatever its name.
 * <p>
 * The check is on the generic type injected by the auto-configured authentication manager
 * resolvers, not on spring-addons' own {@code (Reactive)JwtAbstractAuthenticationTokenConverter}
 * interfaces, so that a plain {@code JwtAuthenticationConverter} bean also replaces the default.
 */
public class DefaultJwtAbstractAuthenticationTokenConverterCondition extends AllNestedConditions {
  DefaultJwtAbstractAuthenticationTokenConverterCondition() {
    super(ConfigurationPhase.REGISTER_BEAN);
  }

  @Conditional(IsOidcResourceServerCondition.class)
  static class SpringAddonsOidcResourceServertEnabled {
  }

  @Conditional(IsJwtDecoderResourceServerCondition.class)
  static class SpringAddonsIntrospectionPropertiesPresent {
  }

  @Conditional(ServletJwtAuthenticationConverterMissing.class)
  static class CustomAuthenticationConverterNotProvided {
  }

  @Conditional(ReactiveJwtAuthenticationConverterMissing.class)
  static class CustomReactiveAuthenticationConverterNotProvided {
  }

  static class ServletJwtAuthenticationConverterMissing
      extends OnMissingBeanOfGenericTypeCondition {
    ServletJwtAuthenticationConverterMissing() {
      super(new ParameterizedTypeReference<Converter<Jwt, ? extends AbstractAuthenticationToken>>() {});
    }
  }

  static class ReactiveJwtAuthenticationConverterMissing
      extends OnMissingBeanOfGenericTypeCondition {
    ReactiveJwtAuthenticationConverterMissing() {
      super(
          new ParameterizedTypeReference<Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>>>() {});
    }
  }
}
