# spring-addons-oauth2 samples

Please start with [tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials) and then clone this repo to run / hack samples.

Samples for different security scenari, with **configuration and unit tests** for
- servlet or reactive apps
- spring's `JwtAuthenticationToken`, Keycloak's [deprecated `KeycloakAuthenticationToken`](https://github.com/keycloak/keycloak/discussions/10187), this repo `OAuthentication<OpenidClaimSet>`
- granted authorities retrieved from the token or from an external source (JPA repo in the sample but could be a web-service)
- usage of test annotations or "fluent API" (MockMvc request post-processors and WebTestClient mutators)

All sample but `webmvc-keycloakauthenticationtoken` make usage of [spring-addons-webmvc-jwt-resource-server](https://github.com/ch4mpy/spring-addons/blob/master/webmvc/spring-addons-webmvc-jwt-resource-server/src/main/java/com/c4_soft/springaddons/security/oauth2/config/synchronised/AddonsSecurityBeans.java) or [spring-addons-webflux-jwt-resource-server](https://github.com/ch4mpy/spring-addons/blob/master/webflux/spring-addons-webflux-jwt-resource-server/src/main/java/com/c4_soft/springaddons/security/oauth2/config/reactive/AddonsSecurityBeans.java) `@AutoConfiguration`.

As a consequence there are 3 sources of configuration for each sample:
- `application.properties` files
- auto-configured beans for servlet or reactive apps
- @Bean overrides in main class (`SampleApi`)

## `Authentication` implementations usablity
Samples makes use of three different `Authentication` but have the same structure: a simple @RestController retrieves messages from a @Service.

Here are the results for the `greet()` method accessing granted authorities and `preffered_username` OpenID claim:

### `JwtAuthenticationToken`
Provided by Spring security. Simple but does not provide OpenID claims accessors.
``` java
public String greet(JwtAuthenticationToken who) {
    return String.format(
        "Hello %s! You are granted with %s.",
        who.getToken().getClaimAsString(StandardClaimNames.PREFERRED_USERNAME),
        who.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
}
```

### `KeycloakAuthenticationToken`
Provided by Keycloak. In my opinion, too adherent to Keycloak.
``` java
public String greet(KeycloakAuthenticationToken who) {
    return String.format(
        "Hello %s! You are granted with %s.",
        who.getAccount().getKeycloakSecurityContext().getIdToken().getPreferredUsername(),
        who.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
}
```

### `OAuthentication<OpenidClaimSet>`
Provided by `spring-addons-webmvc-jwt-resource-server` or `spring-security-oauth2-weflux-addons`. Maybe the most usable / flexible / extensible of the 3
``` java
public String greet(OAuthentication<OpenidClaimSet> who) {
		return String.format(
            "Hello %s! You are granted with %s.",
            who.getToken().getPreferredUsername(),
            who.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
	}
```
