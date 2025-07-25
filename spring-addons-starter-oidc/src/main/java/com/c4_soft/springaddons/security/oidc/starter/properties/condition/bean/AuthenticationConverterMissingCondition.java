package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.ResolvableType;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.jspecify.annotations.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import com.nimbusds.jwt.JWT;

public class AuthenticationConverterMissingCondition implements Condition {

  @Override
  public boolean matches(@NonNull ConditionContext context,
      @NonNull AnnotatedTypeMetadata metadata) {
    return context.getBeanFactory().getBeanNamesForType(ResolvableType.forClassWithGenerics(
        Converter.class, JWT.class, AbstractAuthenticationToken.class)).length < 1;
  }

}
