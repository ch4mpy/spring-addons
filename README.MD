# Spring-addons

Set of tools I find useful to work with Spring-framework.
For now it is focuses on spring-security with OAuth2, but could grow.

## oauth2 library

Java implementation of some OAuth2 concepts.

At beginning, I wrote this just to get a better grasp of the specs, but I ended to use it instead of some Spring classes.

### Claim-sets

Decoded tokens are nothing more than claim-sets which are `Map<String, Object>`.

`ClaimSet` interface extend `Map<String, Object>`, adding helpers to parse `Object` values into something more useful.
It is further specialized in:
 * `ModifiableClaimSet`: handy wile incrementally building a claim-set
 * `UnmodifiableClaimSet`: base class for claim-sets used as `Authentication` property (authentication objects should be immutable)

I also provide two `UnmodifiableClaimSet` extensions: `JwtClaimSet` and `IntrospectionClaiSet`. Each provide accessors for standard claims.

Of course, you are encouraged to extend  `JwtClaimSet` or `IntrospectionClaiSet` or `WithAuthorities` extensions
to add your application private claims, unless you prefer one of `WithAuthorities` specializations from `spring-security-oauth2-addons` as base class (see below).

## spring-security-oauth2-addons

Spring-security authorization mechanism is mostly composed of:
 * an identifier, the "subject" claim in both JWT and introspection
 * a set of granted-authorities

### Choose your way to retrieve authorities

This lib proposes two different ways for resource-servers to associate authorities to an authentication:
 * read it from the "authorities" claim which requires the authorization server to put it there, of course
 * retrieve it from a data-store of its own
 
To help with first solution, I provide `WithAuthorities` interface along with `WithAuthoritiesJwtClaimSet` and `WithAuthoritiesIntrospectionClaimSet`.

I also provide with a sample accessing a H2 table with a JPA repository.

### `OAuth2ClaimSetAuthentication`

This spring-security `Authentication` implementation is designed to work with `ClaimSet` as defined in oauth2 library.
IMO, it is simpler to use and test than `JwtAuthenticationToken` and `OAuth2IntrospectionAuthenticationToken`.

I also provides some tooling around it such as:
 * `OAuth2ClaimSetIntrospectionAuthenticationManager`: an AuthenticationManager implementation to help configure introspection resource servers
 * `ClaimSetGrantedAuthoritiesConverter` a converter from claim-set with embedded authorities to `Collection<GrantedAuthority>` (help configure both JWT resource-servers and above introspection authentication manager)

## spring-security-oauth2-test-addons

Tools to unit-test OAuth2 resource-servers controllers and services with proper authentication objects in security-context.

You'll find there tooling to unit-test controllers and services secured with `OAuth2ClaimSetAuthentication`, of course,
but also `JwtAuthenticationToken` and `OAuth2IntrospectionAuthenticationToken`.
Reason for that is not all features I proposed to contribute to the framework were accepted (introspection testing & annotations), so I kept it there.
 