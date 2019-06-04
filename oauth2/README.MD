# oauth2
Java implementation of some OAuth2 concepts.
At beginning, I wrote this just to get a better grasp of the specs, but I ended to use it instead of some Spring classes:
 * I prefer `JwtClaimSet` over `Jwt`. After all, as written in RFC-7519 a JWT **is a claim-set**.
   Once the token is decoded, I don't see the value of keeping encoded string, headers and signature.
 * I prefer using `IntrospectionClaimSet` over ... `Map<String, Object>`
 * claim-set **are** `Map<String, Object>`. I see only benefits following Object Oriented Design rules and have `ClaimSet` extend `Map<String, Object>`.