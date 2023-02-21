/*
 * Copyright 2020 Jérôme Wacongne.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may
 * obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */
package com.c4_soft.springaddons.security.oauth2.test.annotations;

import java.lang.annotation.Annotation;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import com.c4_soft.springaddons.security.oauth2.test.OpenidClaimSetBuilder;

public abstract class AbstractAnnotatedAuthenticationBuilder<A extends Annotation, T extends Authentication>
        implements WithSecurityContextFactory<A> {

    protected abstract T authentication(A annotation);

    @Override
    public SecurityContext createSecurityContext(A annotation) {
        final var context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication(annotation));

        return context;
    }

    public Set<GrantedAuthority> authorities(String... authorities) {
        return Stream.of(authorities).map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
    }

    public OpenidClaimSetBuilder claims(OpenIdClaims annotation) {
        return OpenIdClaims.Builder.of(annotation).usernameClaim(annotation.usernameClaim());
    }

    @SuppressWarnings("unchecked")
    protected T downcast() {
        return (T) this;
    }
}