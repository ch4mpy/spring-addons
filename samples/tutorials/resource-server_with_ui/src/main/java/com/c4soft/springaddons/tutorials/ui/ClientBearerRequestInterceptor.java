package com.c4soft.springaddons.tutorials.ui;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import feign.RequestInterceptor;
import feign.RequestTemplate;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class ClientBearerRequestInterceptor implements RequestInterceptor {
    private final OAuth2AuthorizedClientRepository authorizedClientRepo;

    @Override
    public void apply(RequestTemplate template) {
        final var auth = SecurityContextHolder.getContext().getAuthentication();
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes servletRequestAttributes) {
            if (auth instanceof OAuth2AuthenticationToken oauth) {
                final var authorizedClient = authorizedClientRepo
                    .loadAuthorizedClient(oauth.getAuthorizedClientRegistrationId(), auth, servletRequestAttributes.getRequest());
                if (authorizedClient != null) {
                    template.header(HttpHeaders.AUTHORIZATION, "Bearer %s".formatted(authorizedClient.getAccessToken().getTokenValue()));
                }
            }
            if (auth instanceof JwtAuthenticationToken jwtAuth) {
                template.header(HttpHeaders.AUTHORIZATION, "Bearer %s".formatted(jwtAuth.getToken().getTokenValue()));
            }
        }
    }
}
