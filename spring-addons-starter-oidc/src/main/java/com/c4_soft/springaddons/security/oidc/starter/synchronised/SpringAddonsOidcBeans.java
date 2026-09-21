package com.c4_soft.springaddons.security.oidc.starter.synchronised;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import com.c4_soft.springaddons.security.oidc.starter.ByIssuerOpenidProviderPropertiesResolver;
import com.c4_soft.springaddons.security.oidc.starter.ClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oidc.starter.ConfigurableClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oidc.starter.OpenidProviderPropertiesResolver;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultAuthoritiesConverterCondition;
import lombok.extern.slf4j.Slf4j;

/**
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@ConditionalOnWebApplication(type = Type.SERVLET)
@AutoConfiguration
@Slf4j
public class SpringAddonsOidcBeans {

  @ConditionalOnMissingBean
  @Bean
  OpenidProviderPropertiesResolver openidProviderPropertiesResolver(
      SpringAddonsOidcProperties addonsProperties) {
    log.debug("Building default OpenidProviderPropertiesResolver with: {}",
        addonsProperties.getOps());
    return new ByIssuerOpenidProviderPropertiesResolver(addonsProperties);
  }

  /**
   * Retrieves granted authorities from a claims-set (decoded from JWT, introspected or obtained
   * from userinfo end-point)
   *
   * <p>
   * Backs off for any bean of type {@code Converter<Map<String, Object>, Collection<? extends
   * GrantedAuthority>>}, whatever its name. With several such beans, the authentication converters
   * and authorities mapper inject the {@code @Primary} one, or else the one named
   * {@code authoritiesConverter}; the context fails to start otherwise.
   * </p>
   *
   * @param authoritiesMappingPropertiesProvider resolves the authorities mapping properties for a
   *        claim-set (by issuer, by default)
   * @return the default authorities converter, configured from properties
   */
  @Conditional(DefaultAuthoritiesConverterCondition.class)
  @Bean
  ClaimSetAuthoritiesConverter authoritiesConverter(
      OpenidProviderPropertiesResolver authoritiesMappingPropertiesProvider) {
    return new ConfigurableClaimSetAuthoritiesConverter(authoritiesMappingPropertiesProvider);
  }
}
