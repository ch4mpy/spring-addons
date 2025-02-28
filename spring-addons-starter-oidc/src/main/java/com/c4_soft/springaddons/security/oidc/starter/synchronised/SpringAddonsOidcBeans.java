package com.c4_soft.springaddons.security.oidc.starter.synchronised;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.context.annotation.Bean;
import com.c4_soft.springaddons.security.oidc.starter.ByIssuerOpenidProviderPropertiesResolver;
import com.c4_soft.springaddons.security.oidc.starter.ClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oidc.starter.ConfigurableClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oidc.starter.OpenidProviderPropertiesResolver;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
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
   * @param addonsProperties spring-addons configuration properties
   * @return
   */
  @ConditionalOnMissingBean
  @Bean
  ClaimSetAuthoritiesConverter authoritiesConverter(
      OpenidProviderPropertiesResolver authoritiesMappingPropertiesProvider) {
    return new ConfigurableClaimSetAuthoritiesConverter(authoritiesMappingPropertiesProvider);
  }
}
