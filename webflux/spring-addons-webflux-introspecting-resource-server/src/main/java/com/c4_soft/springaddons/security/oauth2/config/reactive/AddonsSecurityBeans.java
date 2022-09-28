package com.c4_soft.springaddons.security.oauth2.config.reactive;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;

import com.c4_soft.springaddons.security.oauth2.config.ConfigurableClaimSet2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.OAuth2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;

import lombok.extern.slf4j.Slf4j;

/**
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@EnableWebFluxSecurity
@Configuration
@Slf4j
@Import({ SpringAddonsSecurityProperties.class })
public class AddonsSecurityBeans {

	/**
	 * Retrieves granted authorities from the introspected token attributes according to the configuration set for issuer (iss attribute)
	 *
	 * @param  securityProperties
	 * @return
	 */
	@ConditionalOnMissingBean
	@Bean
	OAuth2AuthoritiesConverter authoritiesConverter(SpringAddonsSecurityProperties securityProperties) {
		log.debug("Building default CorsConfigurationSource with: {}", securityProperties);
		return new ConfigurableClaimSet2AuthoritiesConverter(securityProperties);
	}
}