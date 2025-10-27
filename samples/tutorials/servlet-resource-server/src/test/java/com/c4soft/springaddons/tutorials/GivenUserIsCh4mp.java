package com.c4soft.springaddons.tutorials;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@WithJwt("ch4mp_auth0.json")
public @interface GivenUserIsCh4mp {

}
