package com.c4_soft.springaddons.security.oauth2.test;

import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockBearerTokenAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockJwtAuth;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithOpaqueToken;

/**
 * Exposes the factories behind the test annotations as beans, so that they can be injected in
 * tests (for instance to build {@code Authentication} instances for parameterized tests). The
 * authentication converter each factory runs is looked up in the test context when an
 * authentication is built, as documented on {@link WithJwt#authenticationConverterBeanName()} and
 * {@link WithOpaqueToken#authenticationConverterBeanName()}.
 */
@Order(Ordered.LOWEST_PRECEDENCE)
@AutoConfiguration
public class AuthenticationFactoriesTestConf {

  @Bean
  WithJwt.AuthenticationFactory jwtAuthFactory(ListableBeanFactory beanFactory) {
    return new WithJwt.AuthenticationFactory(beanFactory);
  }

  @Bean
  WithOpaqueToken.AuthenticationFactory opaquetokenAuthFactory(ListableBeanFactory beanFactory) {
    return new WithOpaqueToken.AuthenticationFactory(beanFactory);
  }

  @Bean
  WithMockJwtAuth.JwtAuthenticationTokenFactory mockJwtAuthFactory(
      ListableBeanFactory beanFactory) {
    return new WithMockJwtAuth.JwtAuthenticationTokenFactory(beanFactory);
  }

  @Bean
  WithMockBearerTokenAuthentication.AuthenticationFactory mockBearerTokenAuthFactory(
      ListableBeanFactory beanFactory) {
    return new WithMockBearerTokenAuthentication.AuthenticationFactory(beanFactory);
  }
}
