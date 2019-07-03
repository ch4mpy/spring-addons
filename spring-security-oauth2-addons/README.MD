# spring-security OAuth2 addons

What I propose here are tools to extend spring-security for OAuth2.

1. [Abstract](#abstract)<br/>
2. [Authorities in an OAuth2 multi service application](#multiserviceapp)<br/>
3. [Alternate OAuth2 claims and authentication implementations](#alternateimpls)<br/>

<a name="abstract"/>

## Abstract

I initiated this lib to start working with Spring 5 OAuth2 implementation.

At time I write this, in Spring 5 OAuth2, authorities are embedded in "scope" (or "scp") claim and prefixed with "SCOPE_".
IMO, this is worse practice and scopes should be used to filter authorities and not add to it...

Scopes should be packs of permissions, defined by resource-server to allow the resource-owner control the access he grants different clients with.
Those contracts between clients and resource-owners being defined and stored on the authorization-server, 
 * it should be contained in the token-claims
 * resource-server should insert in the authentication only the sub-set of resource-owner authorities matching the scope

One extreme in scope granularity is social networks APIs: for the user to  finely control what piece of data he grants each client with,
loads of scopes are required.

On the other end, an API designed for a single client (such as an Angular or mobile-app UI) can be happy without a single scope (on / off access).

<a name="multiserviceapp"/>

## Authorities in an OAuth2 multi-service application

I thought of two different ways to associate authorities with a token:

1. the authorization server feeds an "authorities" claim associated to the token (inside the JWT or available at the introspection end-point)
2. the resource server retrieves authorities granted to the token subject (end user ID, client name, ...) from an other source than authorization-server

### Token-claims embedded authorities

It very simple for resource-servers to build authentications as both name and authorities are contained in the token claims but:
 * authorities names are likely to collide between services without a careful namesapce separation
 * tokens can come fat when number of clients grows
 * induces hight coupling on authorities definitions between authorization and resource servers: 
   updating authorities definition for a service could require modifying the authorities service (at least its database)
   which can be an issue when maintained by another team

To mitigate authorities names collisions in token embedded authorities, service names and scopes can be used to define authorities namespaces.
 
For instance, a client needing read / write access to a messaging service would request authentication with `message:read` and `message:write` scopes.
If OAuth2 authorization is granted, the Jwt or Introspection authentication should have `message:read message:write` scope claim and 
also an authorities claim with values such as `[message:read:ROLE_USER, message:write:ROLE_USER, message:write:ROLE_COMPOSER]`. 
Authorities in "message" resource-server `Authentication` would then be [`ROLE_USER`, `ROLE_COMPOSER`],
even if the user actually is granted with `ROLE_ADMIN` for message service (maybe he uses another client for admin tasks)

### Authorities retrieved from an external source with token subject

This clearly is my favorite solution because of the reduced coupling between authorization and resource servers.

Authorization server produces tokens without authorities (just a subject and scopes).
Resource-server retrieves authorities fetching an external source (like a DB) and then restrict it according to token scopes, if relevant.

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

### OAuth2ClaimSetAuthentication<? extends UnmodifiableClaimSet>

`Authentication` implementation which contains just one of above described claim-sets.
IMO easier to build, use and test than `JwtAuthenticationToken` and `OAuth2IntrospectionAuthenticationToken`.

Principal name is "subject" claim.

Authorities are derived from the claim-set by a `Converter`. 
Some implementations just read one of the claims (`WithAuthoritiesJwtClaimSet` and `WithAuthoritiesIntrospectionClaimSet` are designed to embed authorities)
but I also provide samples for converters querying a JPA repository to retrieve authorities granted to a "subject" (authorities **not** provided by the authorization-server).
