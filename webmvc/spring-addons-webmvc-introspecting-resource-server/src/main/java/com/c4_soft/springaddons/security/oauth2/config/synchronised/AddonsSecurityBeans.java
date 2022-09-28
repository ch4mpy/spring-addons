package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.c4_soft.springaddons.security.oauth2.config.ConfigurableClaimSet2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.OAuth2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;

import lombok.extern.slf4j.Slf4j;

/**
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Configuration
@Slf4j
@Import({ SpringAddonsSecurityProperties.class })
public class AddonsSecurityBeans {

	/**
	 * Retrieves granted authorities from the introspected token attributes, according to configuration set for the issuer set in this
	 * attributes
	 *
	 * @param  securityProperties
	 * @return
	 */
	@ConditionalOnMissingBean
	@Bean
	OAuth2AuthoritiesConverter authoritiesConverter(SpringAddonsSecurityProperties securityProperties) {
		log.debug("Building default SimpleJwtGrantedAuthoritiesConverter with: {}", securityProperties);
		return new ConfigurableClaimSet2AuthoritiesConverter(securityProperties);
	}
}