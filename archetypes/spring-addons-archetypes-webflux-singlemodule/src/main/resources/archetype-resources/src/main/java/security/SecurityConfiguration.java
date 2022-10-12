package ${package}.security;

import java.util.Collection;
import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.core.GrantedAuthority;

import com.c4_soft.springaddons.security.oauth2.OAuthentication;
import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;
import com.c4_soft.springaddons.security.oauth2.config.reactive.OAuth2AuthenticationFactory;

import reactor.core.publisher.Mono;

@Configuration
@EnableReactiveMethodSecurity
public class SecurityConfiguration {
	@Bean
	OAuth2AuthenticationFactory authenticationFactory(Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
		return (bearerString, claims) -> Mono.just(new OAuthentication<>(new OpenidClaimSet(claims), authoritiesConverter.convert(claims), bearerString));
	}
}
