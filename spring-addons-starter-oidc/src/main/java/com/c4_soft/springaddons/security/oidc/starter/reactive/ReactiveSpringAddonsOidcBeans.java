package com.c4_soft.springaddons.security.oidc.starter.reactive;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;

import com.c4_soft.springaddons.security.oidc.starter.ByIssuerOpenidProviderPropertiesResolver;
import com.c4_soft.springaddons.security.oidc.starter.ClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oidc.starter.ConfigurableClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oidc.starter.OpenidProviderPropertiesResolver;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsNotServlet;

import lombok.extern.slf4j.Slf4j;

/**
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Conditional(IsNotServlet.class)
@AutoConfiguration
@ImportAutoConfiguration(SpringAddonsOidcProperties.class)
@Slf4j
public class ReactiveSpringAddonsOidcBeans {

    @ConditionalOnMissingBean
    @Bean
    OpenidProviderPropertiesResolver openidProviderPropertiesResolver(SpringAddonsOidcProperties addonsProperties) {
        log.debug("Building default OpenidProviderPropertiesResolver with: {}", addonsProperties.getOps());
        return new ByIssuerOpenidProviderPropertiesResolver(addonsProperties);
    }

    /**
     * Retrieves granted authorities from the Jwt (from its private claims or with the help of an external service)
     *
     * @param securityProperties
     * @return
     */
    @ConditionalOnMissingBean
    @Bean
    ClaimSetAuthoritiesConverter authoritiesConverter(OpenidProviderPropertiesResolver authoritiesMappingPropertiesProvider) {
        return new ConfigurableClaimSetAuthoritiesConverter(authoritiesMappingPropertiesProvider);
    }
}
