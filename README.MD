# Spring-addons
Set of tools I find useful to work with Spring-framework.
For now it is focuses on spring-security with OAuth2, but could grow.

## oauth2 library
Java implementation of some OAuth2 concepts.
At beginning, I wrote this just to get a better grasp of the specs, but I ended to use it instead of some Spring classes:
 * I prefer `JwtClaimSet` over `Jwt`. After all, as written in RFC-7519 a JWT **is a claim-set**.
   Once the token is decoded, I don't see the value of keeping encoded string, headers and signature.
 * I prefer using `IntrospectionClaimSet` over ... `Map<String, Object>`
 * claim-set **are** `Map<String, Object>`. I see only benefits following Object Oriented Design rules and have `ClaimSet` extend `Map<String, Object>`.

## spring-security-oauth2-addons
Introduces a new spring-security `Authentication` implementation based on `ClaimSet` as defined in oauth2 library.
It also provides some tooling around it such as:
 * an AuthenticationManager implementation to help configure introspection resource servers
 * a converter from claim-set with embedded authorities to `Collection<GrantedAuthority>` (help configure both JWT resource-servers and above introspection authentication manager)

## spring-security-oauth2-test-addons
Tools to unit-test OAuth2 resource-servers controllers and services with proper authentication objects in security-context.