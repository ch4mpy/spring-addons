---
title: spring-addons-starter-oidc
nav_order: 3
has_children: true
description: "A Spring Boot starter which configures OAuth2 resource servers and oauth2Login clients from properties, for any OpenID Provider and for several heterogeneous ones at a time."
---

# `spring-addons-starter-oidc`
{: .no_toc }

A Spring Boot starter to use in addition to `spring-boot-starter-oauth2-client` or `spring-boot-starter-oauth2-resource-server` to further **ease OAuth2 configuration with any OpenID Provider, and potentially several heterogeneous ones at a time**.

```xml
<properties>
    <springaddons.version>9.4.0</springaddons.version>
</properties>

<dependencies>
    <!-- the following is a complement (not a replacement) to
    spring-boot-starter-oauth2-resource-server or spring-boot-starter-oauth2-client (or both) -->
    <dependency>
        <groupId>com.c4-soft.springaddons</groupId>
        <artifactId>spring-addons-starter-oidc</artifactId>
        <version>${springaddons.version}</version>
    </dependency>
    <dependency>
        <groupId>com.c4-soft.springaddons</groupId>
        <artifactId>spring-addons-starter-oidc-test</artifactId>
        <version>${springaddons.version}</version>
        <scope>test</scope>
    </dependency>
</dependencies>
```

Use the version displayed by the [Maven Central badge]({{ site.baseurl }}/compatibility/) rather than the one above, which ages.

## What it auto-configures

Depending on the classpath and application properties, `spring-addons-starter-oidc` may autoconfigure up to two security filter chain beans with very low precedence:

- a stateless one with `oauth2ResourceServer` (requests authorization based on `Bearer` access tokens)
- a stateful one with `oauth2Login` (requests authorization based on session cookies)

We may replace any of the auto-configured beans these filter chains are built with.

In the case where more request authorization mechanisms would be needed than the auto-configured ones for OAuth2 (`Basic` auth, API keys, ...), we might define additional filter chains with higher precedence, and strict security-matchers so that the auto-configured filter-chains have a chance to process the requests they should.

## Where to go next

- [Resource servers]({{ site.baseurl }}/oidc/resource-server/), if the application is secured with access tokens and has no session: authorities mapping, authentication converter, multi-tenancy, CORS.
- [Clients with `oauth2Login`]({{ site.baseurl }}/oidc/client/), if the application logs users in and keeps a session: authorization code, RP-Initiated Logout, Back-Channel Logout, CSRF for single-page applications.
- [Basic usage]({{ site.baseurl }}/oidc/usage/) for a minimal working configuration of either, or of both at once.
- [FAQ]({{ site.baseurl }}/oidc/faq/) for Auth0 audiences, Keycloak realms created at runtime, Entra ID, proxies and cookies.
- [Risks and mitigations]({{ site.baseurl }}/oidc/risks/) before adopting.

Choosing between a resource server and a client is the decision which costs the most to get wrong. If a single-page application or a mobile application is involved, the [`bff`](https://github.com/ch4mpy/spring-addons/tree/master/samples/bff) sample is the shape to copy.
