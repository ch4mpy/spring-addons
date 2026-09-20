---
title: Basic usage
parent: spring-addons-starter-oidc
nav_order: 3
description: "Minimal working configurations: a resource server with a JWT decoder, a client with oauth2Login, and an application which is both at once."
---

# Basic usage


This section describes only the most basic usage. For advanced auto-configuration and default overrides, please refer to [the feature pages]({{ site.baseurl }}/oidc/).

**If you are not sure why you need an OAuth2 client with `oauth2Login` (secured with sessions, not access tokens) or an OAuth2 resource server configuration (secured with access tokens, not sessions, but without `oauth2Login`), please read the two features sections above before choosing.** This might save you a lot of time and effort.

Add `com.c4-soft.springaddons:spring-addons-starter-oidc` to your dependencies, in addition to `org.springframework.boot:spring-boot-starter-oauth2-client` or `org.springframework.boot:spring-boot-starter-oauth2-resource-server`.

If configuring an OAuth2 client (with `oauth2Login`), define the standard Spring Boot `provider` and `registration` properties for OAuth2 clients.

If configuring an OAuth2 resource server with access token introspection, define the standard Spring Boot `opaquetoken` properties.

Then, define the relevant `com.c4-soft.springaddons.oidc` properties for your use case. There are runnable [samples](https://github.com/ch4mpy/spring-addons/tree/master/samples) you should refer to, but here are a few demos for different use-cases and OpenID Providers:

## Resource Server with JWT decoder

For a REST API secured with JWT access tokens, you need:
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <!-- For a reactive application, use spring-boot-starter-webflux instead -->
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>

<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starter-oidc</artifactId>
</dependency>
```
And
```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        ops:
        - iss: https://oidc.c4-soft.com/auth/realms/master
          username-claim: preferred_username
          authorities:
          - path: $.realm_access.roles
          - path: $.resource_access.*.roles
        resourceserver:
          permit-all:
          - "/greet/public"
          cors:
          - path: /**
            allowed-origin-patterns: http://localhost:4200
```
Above configuration will create an application without sessions nor CSRF protection, and 401 will be answered to unauthorized requests to protected resources.

## Client

For an app serving Thymeleaf templates with login and logout:
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <!-- For a reactive application, use spring-boot-starter-webflux instead -->
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-thymeleaf</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>

<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starter-oidc</artifactId>
</dependency>
```
And
```yaml
cognito-issuer: https://cognito-idp.us-west-2.amazonaws.com/us-west-2_RzhmgLwjl
cognito-client-id: change-me
cognito-secret: change-me

spring:
  security:
    oauth2:
      client:
        provider:
          cognito:
            issuer-uri: ${cognito-issuer}
        registration:
          cognito-authorization-code:
            authorization-grant-type: authorization_code
            client-id: ${cognito-client-id}
            client-secret: ${cognito-secret}
            provider: cognito
            scope: openid,profile,email,offline_access
com:
  c4-soft:
    springaddons:
      oidc:
        ops:
        - iss: ${cognito-issuer}
          username-claim: username
          authorities:
          - path: cognito:groups
        client:
          security-matchers:
          - /**
          permit-all:
          - /login/**
          - /oauth2/**
          - /
          # Auth0 and Cognito do not follow strictly the OpenID RP-Initiated Logout spec and need specific configuration
          oauth2-logout:
            cognito-authorization-code:
              uri: https://spring-addons.auth.us-west-2.amazoncognito.com/logout
              client-id-request-param: client_id
              post-logout-uri-request-param: logout_uri
```
Above configuration will create an application secured with sessions (not access tokens), with CSRF protection enabled, and unauthorized requests to protected resources will be redirected to login.

## Client and Resource Server

For an app exposing publicly both
- Thymeleaf templates secured with session (with login and logout), all templates being served with `/ui` prefix (but index which is at `/`)
- a REST API secured with access token
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <!-- In a reactive application, use only spring-boot-starter-webflux -->
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <!-- Used for WebClient to call the REST API from controllers serving Thymeleaf templates -->
    <artifactId>spring-boot-starter-webflux</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-thymeleaf</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>

<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starter-oidc</artifactId>
</dependency>
```
And
```yaml
auth0-issuer: https://oidc.c4-soft.com/auth/realms/master
auth0-client-id: change-me
auth0-secret: change-me

spring:
  security:
    oauth2:
      client:
        provider:
          auth0:
            issuer-uri: ${auth0-issuer}
        registration:
          auth0-authorization-code:
            authorization-grant-type: authorization_code
            client-id: ${auth0-client-id}
            client-secret: ${auth0-secret}
            provider: auth0
            scope: openid,profile,email,offline_access
com:
  c4-soft:
    springaddons:
      oidc:
        ops:
        - iss: ${auth0-issuer}
          username-claim: $['https://c4-soft.com/user']['name']
          authorities:
          - path: $['https://c4-soft.com/user']['roles']
          - path: $.permissions
        client:
          security-matchers:
          - /login/**
          - /oauth2/**
          - /logout
          - /
          - /ui/**
          permit-all:
          - /login/**
          - /oauth2/**
          - /
          # Auth0 and Cognito do not follow strictly the OpenID RP-Initiated Logout spec and need specific configuration
          oauth2-logout:
            auth0-authorization-code:
              uri: ${auth0-issuer}v2/logout
              client-id-request-param: client_id
              post-logout-uri-request-param: returnTo
          # Auth0 requires an "audience" parameter in authorization-code request to deliver JWTs
          authorization-params:
            auth0-authorization-code:
              audience: demo.c4-soft.com
        resourceserver:
          permit-all:
          - "/greet/public"
```
With the above configuration, two distinct security filter chains will be defined:
- a client one with sessions (and CSRF protection enabled), intercepting all requests to UI templates as well as those involved in login and logout, and redirecting to login unauthorized requests to protected templates.
- a resource server one acting as default (with lowest precedence to process all requests that were not matched with client filter chain `securityMatchers`), without sessions (requests are secured with JWT access tokens) nor CSRF protections, and returning 401 to unauthorized requests to protected resources.
