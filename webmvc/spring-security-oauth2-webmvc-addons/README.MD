# spring-security OAuth2 addons

## spring-boot resource-server auto-configuration

This lib offers spring-boot auto-configuration for OpenID resource-servers with sensible default which can be overridden from properties file:
* "stateless" sessions
* disabled CSRF
* 401 instead of redirection to login
* anonymous enabled
* authorities from `realm_access.roles` claims. You can provide a list of claims and specify basic post processing (force upper-case and add prefix)

The configured `Authentication` implementation is `OAuthentication<OpenidClaimSet>`, which is intended to be used with any OpenID authorization server (Keycoak, Auth0, MS Identity Server, ...).
Here are few key features when compared to `JwtAuthenticationToken` or `BearerTokenAuthentication`:
 * fine grained CORS configuration per path
 * you define which claims to get authorities from for each authorization-server (token-issuer) and with which prefix and case
 * principal and credentials are typed with something more actionable than `Object`
 * structure as close as possible to the OpenID standard

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
	  
	  // ExpressionInterceptUrlRegistryPostProcessor is a bean you might want to provide explicitly for routes neither public nor requiring just isAuthenticated()
	}
}
```
Here is what is configurable from properties file. At least one authorization-server location must be configured
``` properties
# This must be configured with valid URL such as https://localhost:9443/auth/realms/master
com.c4-soft.springaddons.security.token-issuers[0].location=

# This is where you define a comma separated list of claims to get authorities from
com.c4-soft.springaddons.security.token-issuers[0].authorities.claims=realm_access.roles,permissions
com.c4-soft.springaddons.security.token-issuers[0].authorities.prefix=
com.c4-soft.springaddons.security.token-issuers[0].authorities.caze=

# CORS config (per path). If com.c4-soft.springaddons.security.cors array is empty, CORS is disabled
com.c4-soft.springaddons.security.cors[0].path=/**
# Those are defaults you can omit
com.c4-soft.springaddons.security.cors[0].allowedOrigins=*
com.c4-soft.springaddons.security.cors[0].allowedMethods=*
com.c4-soft.springaddons.security.cors[0].allowedHeaders=*
com.c4-soft.springaddons.security.cors[0].exposedHeaders=*

# Those are defaults you can omit
com.c4-soft.springaddons.security.csrf-enabled=false
com.c4-soft.springaddons.security.anonymous-enabled=true
com.c4-soft.springaddons.security.permit-all=/actuator/health/readiness,/actuator/health/liveness,/v3/api-docs/**
com.c4-soft.springaddons.security.redirect-to-login-if-unauthorized-on-restricted-content=false
com.c4-soft.springaddons.security.statless-sessions=true
```

For complete samples, please refer to [`samples` module](https://github.com/ch4mpy/spring-addons/tree/master/samples).
