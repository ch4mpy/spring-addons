# spring-security OAuth2 addons

What I propose here are tools to extend spring-security for OAuth2.

1. [Abstract](#abstract)<br/>
2. [Authorities in an OAuth2 multi service application](#multiserviceapp)<br/>
3. [Alternate OAuth2 claims and authentication implementations](#alternateimpls)<br/>

<a name="abstract"/>

## Abstract

I initiated this lib to start working with Spring 5 OAuth2 implementation.

At time I write this, in Spring 5 OAuth2, authorities are embedded in "scope" (or "scp") claim and prefixed with "SCOPE_".

The prefix is irritating when it comes to porting an existing app to OAuth2 (requires to modify security expressions), but not a major obstacle.

Mixing "scope" and "authorities concepts might be a deeper problem as, IMO, it should serve different purposes:
* authorities should define what a user is allowed to do in an information system
* scopes should define what authorities a user delegates to a client (what subset of his authorities he grants a service with)

I put here what I found helpful to build my projects faster.

<a name="multiserviceapp"/>

## Authorities in an OAuth2 multi-service application

I thought of two different ways to associate authorites with a token:

1. the authorization server feeds an "authorities" claim associated to the token (inside the JWT or available at the introspection end-point)
2. the resource server retrieves authorities granted to the token subject (end user ID, client name, ...) from an other source than authorization-server

First solution makes it very simple for resource-servers to build authentications as both name and authorities are contained in the token claims but:
 * authorities names are likely to collide between services without a careful namesapce separation
 * tokens can come fat when number of clients grows
 * induces hight coupling on authorities definitions between authorization and resource servers: 
   updating authorities definition for a service could require modifying the authorities service (at least its database)
   which can be an issue when maintained by another team

To mitigate authorities names collisions in token embedded authorities, scopes can be used to define authorities namespaces.
 
For instance, a client needing access to a messaging service would request authentication with "message" scope.
If OAuth2 authorization is granted, the Jwt or Introspection authentication should have "message" scope-claim and 
also an authorities claim with values such as "message:read message:write". 
Authorities in "message" resource-server `Authentication` would then be {"read", "write"}

For single sign on servers with many clients, best solution might be producing tokens without authorities (just a subject) 
and letting each resource-server retrieve authorities fetching an other source like a DB

<a name="alternateimpls"/>

## Alternate OAuth2 claims and authentication implementations

Following my path to building authentications a new way, I ended with new OAuth2 authentication implementations:
after all, claim-sets are just enough to manage all security once JWT are decoded or opaque tokens introspected.
 
Also, translating some of the OAuth2 specs to java helped me better grasp it. It also provided me we classes I believe more handy than some spring-security ones.

### JWT and introspection claim-sets

By definition, a claim-set **is** `Map<String, Object>`, so all claim-set implementations in this lib extend `Map<String, Object>`.

It is handy for claim-sets to be mutable at build time, but once in an authentication it should be immutable.
I provide with MutableClaimSet, but both `JwtClaimSet` and `IntrospectionClaimSet` extend `ImmutableClaimSet`.

Also, it is frequent to have an authorization-server produce tokens containing both user identity ("subject" claim) and grants ("authorities" claim).
`WithAuthoritiesJwtClaimSet` and `WithAuthoritiesIntrospectionClaimSet` specializations serve that purpose.

### OAuth2ClaimSetAuthentication

`Authentication` implementation which contains just one of above described claim-sets.
IMO easier to build, use and test than `JwtAuthenticationToken` and `OAuth2IntrospectionAuthenticationToken`.

Principal name is "subject" claim.

Authorities are derived from the claim-set by a `Converter`. 
Some implementations just read one of the claims (`WithAuthoritiesJwtClaimSet` and `WithAuthoritiesIntrospectionClaimSet` are designed to embed authorities)
but I also provide samples for converters querying a JPA repository to retrieve authorities granted to a "subject" (authorities **not** provided by the authorization-server).
