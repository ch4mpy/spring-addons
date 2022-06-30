# spring-security OAuth2 addons

## spring-boot resource-server auto-configuration

This lib offers spring-boot auto-configuration for OpenID resource-servers with sensible default which can be overridden from properties file:
- OIDC authorization-server `issuer` URI (can configure just one or as as many as you need for multi-tenant scenarios)
- convenient granted-authorities mapping: source claims of course (not just `scope`), but also prefix and case processing
- fine grained CORS configuration (per path)
- 401 (unauthorized) instead of 302 (redirect to login) when authentication is missing or invalid on protected end-point
- enabled anonymous
- list of "permit-all" routes accesssible to anonymous
- default security to `isAuthenticated()` (all routes which are not listed in "permit-all")
- "stateless" session management
- disabled CSRF

The configured `Authentication` implementation is `OAuthentication<OpenidClaimSet>`, which is intended to be used with any OpenID authorization server (Keycoak, Auth0, MS Identity Server, ...).

## Usage

All you need is declare a dependency on `spring-security-oauth2-webmvc-addons` and define a few properties.

You might use any OIDC authorization-server (including Keycloak).

``` xml
    <dependencies>
        <dependency>
            <groupId>com.c4-soft.springaddons</groupId>
            <artifactId>spring-security-oauth2-webmvc-addons</artifactId>
            <version>${com.c4-soft.springaddons.version}</version>
        </dependency>
    </dependencies>
```
``` java
@SpringBootApplication
public class SampleApi {
	public static void main(String[] args) {
		new SpringApplicationBuilder(SampleApi.class).web(WebApplicationType.SERVLET).run(args);
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class WebSecurityConfig {
	  // browse com.c4_soft.springaddons.security.oauth2.config.synchronised.ServletSecurityBeans
	  // for auto-configuration you can override here
	}
}
```
``` properties
# This must be configured with valid URL such as https://localhost:9443/auth/realms/master
com.c4-soft.springaddons.security.token-issuers[0].location=

# This is where you define a comma separated list of claims to get authorities from
com.c4-soft.springaddons.security.token-issuers[0].authorities.claims=realm_access.roles,permissions
# Those are defaults you can omit
com.c4-soft.springaddons.security.token-issuers[0].authorities.prefix=
com.c4-soft.springaddons.security.token-issuers[0].authorities.caze=unchanged

# CORS config (per path). If com.c4-soft.springaddons.security.cors array is empty, CORS is disabled
com.c4-soft.springaddons.security.cors[0].path=/greet/**
# Those are defaults you can omit
com.c4-soft.springaddons.security.cors[0].allowedOrigins=*
com.c4-soft.springaddons.security.cors[0].allowedMethods=*
com.c4-soft.springaddons.security.cors[0].allowedHeaders=*
com.c4-soft.springaddons.security.cors[0].exposedHeaders=*

# Those are defaults you can omit
com.c4-soft.springaddons.security.csrf-enabled=false
# When permit-all is not empty, anonymous is enabled
com.c4-soft.springaddons.security.permit-all=/actuator/health/readiness,/actuator/health/liveness,/v3/api-docs/**
com.c4-soft.springaddons.security.redirect-to-login-if-unauthorized-on-restricted-content=false
com.c4-soft.springaddons.security.statless-sessions=true
```

## How the magic happens
This lib uses the new spring-boot (2.7 and above) auto-configuration: as per `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` content, `ServletSecurityBeans` is auto-configured. This configuration clas does two things:
- `@Import({ SpringAddonsSecurityProperties.class })`: this enables `com.c4-soft.springaddons.security.*` properties
- define all required web-security beans

## Configuration overrides
All beans declared in `ServletSecurityBeans` are decorated with `@ConditionalOnMissingBean`. This means you can override any component just by defining bean of the same type in your app. Do not easitate to open sources

Here are the beans you might like to override (you might refer to `ServletSecurityBeans` sources to get inspiration):
- `ExpressionInterceptUrlRegistryPostProcessor`: define security policy for non "permit-all" routes. Default requires users to be authenticated (not anonymous)
- `SynchronizedJwt2AuthenticationConverter<>`: switch `Authentication` instances from `OAuthentication<>` to any other implementation of your choice
- `Jwt2AuthoritiesConverter`: switch authorities converter to something completely at your hand
- `SynchronizedJwt2OpenidClaimSetConverter`: use claim-set of other type than `OpenidClaimSet` (anything that emplements `Map<String, Object> & Serializable` should be accepted
- `HttpSecurityPostProcessor`: post-process HttpSecurity after it was pre-configured according to `com.c4-soft.springaddons.security.*` properties. This enables to **change anything preconfigured in this lib** in case the four preciding were not enough.

You should not override those 2 (you can, but if you have to, please open a ticket, there's something I might have missed):
- `JwtIssuerAuthenticationManagerResolver`: enables mutli-tenancy
- `SecurityFilterChain`: sets-up everything else. If you override it, you`ll likely break this lib auto-configuration

## samples
For complete samples, please refer to [`samples` module](https://github.com/ch4mpy/spring-addons/tree/master/samples).
