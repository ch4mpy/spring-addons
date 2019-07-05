# oauth2
Java implementation of some OAuth2 concepts I originally wrote to get a better grasp of the specs, but I ended to use it instead of some Spring classes:
 * I prefer `JwtClaimSet` over `Jwt`. After all, as written in RFC-7519 a JWT **is a claim-set**.
   I don't see the value of keeping encoded string, headers and signature in `Authentication` object: this is meta-data required for decoding the token, not actual token data.
 * I prefer using `IntrospectionClaimSet` over `Map<String, Object>` (richer API)

## Claim-sets

Decoded tokens are nothing more than claim-sets which are `Map<String, Object>`.

I see only benefits following Object Oriented Design rules and have `ClaimSet` extend `Map<String, Object>`, 
adding helpers to parse `Object` values into something more useful.

It is further specialized in:
 * `ModifiableClaimSet`: handy wile incrementally building a claim-set
 * `UnmodifiableClaimSet`: base class for claim-sets used as `Authentication` property (authentication objects should be immutable)

I also provide two `UnmodifiableClaimSet` extensions: `JwtClaimSet` and `IntrospectionClaiSet`. Each providing getters for standard claims.

Of course, you are encouraged to extend  `JwtClaimSet` or `IntrospectionClaiSet` to add your application private claims,
unless you prefer to have authorities contained in token claims and then extend one of `WithAuthorities` specializations from 
[`spring-security-oauth2-addons`](https://github.com/ch4mpy/spring-addons/tree/master/spring-security-oauth2-addons).