# spring-addons-oauth2 samples

Please start with [tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials) and then clone this repo to run / hack samples.

Samples for different security scenarios, with **configuration, unit and integration tests** for
- servlet (webmvc) / reactive (weblux) apps
- JWT decoder / access token introspection
- spring's `JwtAuthenticationToken` (JWT decoder) or `BearerTokenAuthentication` (introspection) / this repo `OAuthentication<OpenidClaimSet>`
- granted authorities retrieved from the token or from an external source (JPA repo in the sample but could be a web-service)
- usage of test annotations or "fluent API" (MockMvc request post-processors and WebTestClient mutators)

All sample using of this repo starters `@AutoConfiguration`, there are 3 sources of configuration:
- `application.properties` files
- auto-configured beans for servlet or reactive apps
- @Bean overrides in main class

## `Authentication` implementations usability
Samples makes use of three different `Authentication` but have the same structure: a simple `@RestController` retrieves messages from a `@Service` which in turn uses a `@Repository`.

Here are the results for the `greet()` method accessing granted authorities and `preffered_username` OpenID claim:

### `JwtAuthenticationToken`
Provided by Spring security with JWT decoder. Simple but does not provide OpenID claims accessors.
``` java
public String greet(JwtAuthenticationToken who) {
    return String.format(
        "Hello %s! You are granted with %s.",
        who.getToken().getClaimAsString(StandardClaimNames.PREFERRED_USERNAME),
        who.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
}
```

### `BearerTokenAuthentication`
Similar to above for access token introspection.
``` java
public String greet(BearerTokenAuthentication who) {
    return String.format(
            "Hello %s! You are granted with %s.",
            who.getTokenAttributes().get(StandardClaimNames.PREFERRED_USERNAME),
            who.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
}
```

### `OAuthentication<OpenidClaimSet>`
Provided by `spring-addons-starter-oidc` with a `Converter<Jwt, ? extends AbstractAuthenticationToken>`. Maybe the most usable / flexible / extensible of the 3
``` java
public String greet(OAuthentication<OpenidClaimSet> who) {
    return String.format(
        "Hello %s! You are granted with %s.",
        who.getToken().getPreferredUsername(),
        who.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
}
```
