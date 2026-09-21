package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.ResolvableType;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.type.AnnotatedTypeMetadata;
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

  /**
   * Same check as Spring Boot's {@code @ConditionalOnMissingBean} for a generic type: no bean
   * definition (in this context or its ancestors) whose type matches, without eager initialization.
   */
  private abstract static class OnMissingBeanOfType implements Condition {
    private final ResolvableType type;

    OnMissingBeanOfType(ParameterizedTypeReference<?> type) {
      this.type = ResolvableType.forType(type);
    }

    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
      final ListableBeanFactory beanFactory = context.getBeanFactory();
      return beanFactory == null || BeanFactoryUtils
          .beanNamesForTypeIncludingAncestors(beanFactory, type, true, false).length == 0;
    }
  }

  static class ServletJwtAuthenticationConverterMissing extends OnMissingBeanOfType {
    ServletJwtAuthenticationConverterMissing() {
      super(new ParameterizedTypeReference<Converter<Jwt, ? extends AbstractAuthenticationToken>>() {});
    }
  }

  static class ReactiveJwtAuthenticationConverterMissing extends OnMissingBeanOfType {
    ReactiveJwtAuthenticationConverterMissing() {
      super(
          new ParameterizedTypeReference<Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>>>() {});
    }
  }
}
