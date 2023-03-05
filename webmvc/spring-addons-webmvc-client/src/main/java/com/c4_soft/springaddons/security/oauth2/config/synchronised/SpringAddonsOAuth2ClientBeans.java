package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import com.c4_soft.springaddons.security.oauth2.config.ConfigurableClaimSet2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oauth2.config.OAuth2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsOAuth2ClientProperties;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsOAuth2LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;

/**
 * The following {@link ConditionalOnMissingBean &#64;ConditionalOnMissingBeans}
 * are auto-configured
 * <ul>
 * <li>oAuth2AuthorizationRequestResolver: a
 * {@link OAuth2AuthorizationRequestResolver}. Default instance is a
 * {@link SpringAddonsOAuth2AuthorizationRequestResolver} which sets the client
 * hostname
 * in the
 * redirect URI with
 * {@link SpringAddonsOAuth2ClientProperties#getClientUri()
 * SpringAddonsOAuth2ClientProperties#client-uri}</li>
 * <li>logoutSuccessHandler: a {@link LogoutSuccessHandler}. Default
 * instance is a {@link SpringAddonsOAuth2LogoutSuccessHandler} which logs a
 * user out
 * from the authorization servers he last logged on</li>
 * <li>authoritiesConverter: an {@link OAuth2AuthoritiesConverter}. Default
 * instance is a {@link ConfigurableClaimSet2AuthoritiesConverter} which reads
 * spring-addons {@link SpringAddonsSecurityProperties}</li>
 * <li>grantedAuthoritiesMapper: a {@link GrantedAuthoritiesMapper} using the
 * already configured {@link OAuth2AuthoritiesConverter}</li>
 * </ul>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@AutoConfiguration
@Import({ SpringAddonsOAuth2ClientProperties.class })
public class SpringAddonsOAuth2ClientBeans {

    @ConditionalOnMissingBean
    @Bean
    OAuth2AuthorizationRequestResolver oAuth2AuthorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository,
            SpringAddonsOAuth2ClientProperties clientProps) {
        return new SpringAddonsOAuth2AuthorizationRequestResolver(clientRegistrationRepository,
                clientProps.getClientUri());
    }

    @ConditionalOnMissingBean
    @Bean
    LogoutRequestUriBuilder logoutRequestUriBuilder(
            InMemoryClientRegistrationRepository clientRegistrationRepository,
            SpringAddonsOAuth2ClientProperties clientProps) {
        return new SpringAddonsOAuth2LogoutRequestUriBuilder(clientProps);
    }

    @ConditionalOnMissingBean
    @Bean
    LogoutSuccessHandler logoutSuccessHandler(LogoutRequestUriBuilder logoutRequestUriBuilder,
            OAuth2AuthorizedClientService authorizedClients) {
        return new SpringAddonsOAuth2LogoutSuccessHandler(logoutRequestUriBuilder, authorizedClients);
    }

    @ConditionalOnMissingBean
    @Bean
    OAuth2AuthoritiesConverter authoritiesConverter(SpringAddonsSecurityProperties addonsProperties) {
        return new ConfigurableClaimSet2AuthoritiesConverter(addonsProperties);
    }

    @ConditionalOnMissingBean
    @Bean
    GrantedAuthoritiesMapper grantedAuthoritiesMapper(
            Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            authorities.forEach(authority -> {
                if (authority instanceof OidcUserAuthority oidcAuth) {
                    mappedAuthorities.addAll(authoritiesConverter.convert(oidcAuth.getIdToken().getClaims()));

                } else if (authority instanceof OAuth2UserAuthority oauth2Auth) {
                    mappedAuthorities.addAll(authoritiesConverter.convert(oauth2Auth.getAttributes()));

                }
            });

            return mappedAuthorities;
        };
    }
}