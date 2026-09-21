package com.c4_soft.springaddons.security.oauth2.test.annotations;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.BeanNotOfRequiredTypeException;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.core.ResolvableType;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

/**
 * Picks the authentication converter bean a test annotation runs, with the same rule as
 * {@code spring-addons-starter-oidc} applies when injecting it in its security filter-chain:
 * <ol>
 * <li>the bean named by the annotation's {@code authenticationConverterBeanName}, when set;</li>
 * <li>the single candidate of the servlet type, or the {@code @Primary} one;</li>
 * <li>among several servlet candidates, the one with the starter's default bean name;</li>
 * <li>the same for the reactive type;</li>
 * <li>nothing, when no candidate is defined: the caller applies its own default.</li>
 * </ol>
 * Several candidates without a preference is an error, as it would be at runtime.
 *
 * @param <S> the servlet converter type
 * @param <R> the reactive converter type
 */
final class AuthenticationConverterLookup<S, R> {
  private final @Nullable ListableBeanFactory beanFactory;
  private final Optional<S> fixedServletConverter;
  private final Optional<R> fixedReactiveConverter;
  private final ResolvableType servletType;
  private final ResolvableType reactiveType;
  private final String defaultBeanName;

  /**
   * @param beanFactory the test context
   * @param servletType the type of servlet converters
   * @param reactiveType the type of reactive converters
   * @param defaultBeanName the name of the bean {@code spring-addons-starter-oidc} auto-configures
   *        (and picks among several candidates)
   */
  AuthenticationConverterLookup(ListableBeanFactory beanFactory, ResolvableType servletType,
      ResolvableType reactiveType, String defaultBeanName) {
    this.beanFactory = beanFactory;
    this.fixedServletConverter = Optional.empty();
    this.fixedReactiveConverter = Optional.empty();
    this.servletType = servletType;
    this.reactiveType = reactiveType;
    this.defaultBeanName = defaultBeanName;
  }

  /**
   * Backward compatibility for the factories' constructors which take the converters themselves
   * (kept on the 8.x line): no lookup in a test context, the servlet converter is used when given,
   * else the reactive one, as it used to be.
   *
   * @param servletConverter the servlet converter to use, if any
   * @param reactiveConverter the reactive converter to use when there is no servlet one
   */
  AuthenticationConverterLookup(Optional<S> servletConverter, Optional<R> reactiveConverter) {
    this.beanFactory = null;
    this.fixedServletConverter = servletConverter;
    this.fixedReactiveConverter = reactiveConverter;
    this.servletType = ResolvableType.NONE;
    this.reactiveType = ResolvableType.NONE;
    this.defaultBeanName = "";
  }

  /**
   * @param <T> the type of the result
   * @param beanName the converter bean name from the annotation ("" when not set)
   * @param servlet what to do with a servlet converter
   * @param reactive what to do with a reactive converter
   * @return the result of the function applied to the selected converter, or empty when no converter
   *         bean is defined
   */
  @SuppressWarnings("unchecked")
  <T> Optional<T> apply(String beanName, Function<S, T> servlet, Function<R, T> reactive) {
    if (beanFactory == null) {
      if (StringUtils.hasText(beanName)) {
        throw new IllegalStateException(
            "authenticationConverterBeanName is set to '%s' but this factory was built with explicit converters, not from a test context: use the constructor taking a ListableBeanFactory"
                .formatted(beanName));
      }
      return fixedServletConverter.map(servlet)
          .or(() -> fixedReactiveConverter.map(reactive));
    }
    if (StringUtils.hasText(beanName)) {
      final var bean = beanFactory.getBean(beanName);
      if (beanFactory.isTypeMatch(beanName, servletType)) {
        return Optional.ofNullable(servlet.apply((S) bean));
      }
      if (beanFactory.isTypeMatch(beanName, reactiveType)) {
        return Optional.ofNullable(reactive.apply((R) bean));
      }
      throw new BeanNotOfRequiredTypeException(beanName, servletType.toClass(), bean.getClass());
    }
    final var servletConverter = select(servletType);
    if (servletConverter.isPresent()) {
      return Optional.ofNullable(servlet.apply((S) servletConverter.get()));
    }
    return select(reactiveType).map(c -> reactive.apply((R) c));
  }

  private Optional<Object> select(ResolvableType type) {
    final List<String> names = Arrays
        .asList(BeanFactoryUtils.beanNamesForTypeIncludingAncestors(beanFactory, type, true, false));
    if (names.isEmpty()) {
      return Optional.empty();
    }
    final var unique = beanFactory.getBeanProvider(type).getIfUnique();
    if (unique != null) {
      return Optional.of(unique);
    }
    if (names.contains(defaultBeanName)) {
      return Optional.of(beanFactory.getBean(defaultBeanName));
    }
    throw new NoUniqueBeanDefinitionException(type.toClass(), names.size(),
        "%d beans of type %s found: %s. Mark one @Primary, name it '%s' (the one spring-addons-starter-oidc injects in its security filter-chain), or set authenticationConverterBeanName on the test annotation."
            .formatted(names.size(), type, names, defaultBeanName));
  }
}
