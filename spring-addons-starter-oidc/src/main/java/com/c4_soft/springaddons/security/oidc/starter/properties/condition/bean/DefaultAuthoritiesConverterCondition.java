package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import java.util.Collection;
import java.util.Map;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;

/**
 * Matches when the default {@code authoritiesConverter} bean should be created: no bean converting
 * a claim-set to authorities is defined, whatever its name. The check is on the generic type the
 * authentication converters and the authorities mapper inject, not on spring-addons' own
 * {@code ClaimSetAuthoritiesConverter} interface, so that any
 * {@code Converter<Map<String, Object>, Collection<? extends GrantedAuthority>>} bean replaces the
 * default.
 */
public class DefaultAuthoritiesConverterCondition extends OnMissingBeanOfGenericTypeCondition {
  DefaultAuthoritiesConverterCondition() {
    super(
        new ParameterizedTypeReference<Converter<Map<String, Object>, Collection<? extends GrantedAuthority>>>() {});
  }
}
