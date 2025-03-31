package com.c4soft.springaddons.tutorials;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import com.c4_soft.springaddons.security.oauth2.test.annotations.ClasspathClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockJwtAuth;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@WithMockJwtAuth(claims = @OpenIdClaims(jsonFile = @ClasspathClaims("ch4mp_auth0.json")))
public @interface GivenUserIsCh4mpDeprecated {

}
