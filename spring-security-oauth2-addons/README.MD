# spring-security OAuth2 addons

What I propose here are tools to extend spring-security for OAuth2.

1. [Abstract](#abstract)<br/>
2. [Scopes & Authorities](#scopes-authorities)<br/>
3. [Alternate OAuth2 claims and authentication implementations](#alternateimpls)<br/>

As I now publish this lib on maven-central, something like following Maven configuration should be enough (remember to define `com.c4-soft.springaddons.version` property):
``` xml
	<dependencies>
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<artifactId>spring-security-oauth2-addons</artifactId>
			<version>${com.c4-soft.springaddons.version}</version>
		</dependency>
	</dependencies>
```

<a name="abstract"/>

## Why not sticking to spring-security ?

I'm not a great fan of spring OAuth2 token abstractions and `Authentication` implementations.
I think there is no reason to put stuff like decoding meta-data or opaque strings in `Authentication` objects and 
that a single generic OAuth2 implementation is easier to use, specially when it comes to testing.
Jump to [Alternate OAuth2 claims and authentication implementations](#alternateimpls) to get an idea of what alternative I propose.

Also, IMO, scopes should not be used as authorities container. It is designed for the resource-owner to define what subsets of the resources he owns a client can access.
I then prefer to think of scopes as authorities filters (a "scoped" view of authorities set will be a subset of resource-owner authorities). More on that below.

<a name="scopes-authorities"/>

## Scopes and authorites

### Scopes
As explained in introduction, IMO scopes should be packs of permissions for the resource-owner control the access he grants different clients with to resources he owns.

Lets illustrate how different the relation between scopes and authorities can be with two extreme samples:
 * social-network resource-server with many "untrusted" clients: 
   almost a scope per authority for the user to define precisely what he allows each client can access (age, gender, phone, friends, etc.)
 * resource server with a single trusted client (back-end for mobile or Angular application for instance): no scope at all required. 
   If user authenticates with the client, then full access is granted (in the user's limits, off course)
   
Additionally, there is no requirement for authorities to be contained in token claims.
It is possible to use a private claim for that, and this lib will help you do it if that's what you want to do,
but there are good reasons to choose a solution where resource-servers retrieve authorities to grant an OAuth2 authentication with based on token subject and scopes.

### Authorities converters
as exposed above, two scenarios:
1. the authorization-server provides with ready-to-use authorities in a token claim (inside the JWT or available at the introspection end-point)
2. the resource-server retrieves authorities granted to the token subject (end user ID, client name, ...) from an other source than authorization-server and filters through scopes

### Token-claims embedded authorities

If authorization-server puts already "scoped" authorities in a private claim (`authorities` is assumed in this lib),
it is then very simple for resource-servers to build authentications as both name and authorities are contained in the token claims but:
 * authorities names are likely to collide between services without a careful name-space separation
 * tokens can come fat when number of clients and resource-servers grows
 * induces high coupling on authorities definitions between authorization and resource servers: 
   updating authorities definition for a service could require modifying the authorities service (at least its database)
   which can be an issue when maintained by another team

An easy way to prevent authorities names collisions - and for a given resource-server to figure out which authorities it should consider when reading a token -
is to use resource-server name as authorities prefix (for instance pre-pending authorities with `showcase:` as done in samples module).
I do not provide with authorization-server logic to store authorities nor "scope" it before feeding `authorities` claim.
I don't neither provide with authorities transformation on resource-server. So, you'll have to add prefixes on authorization-server and, 
if you prefer resource-server security expressions not know about this prefixes, filter and transform authorities in appropriate `Converter` on resource-server.

### Authorities retrieved from an external source with token subject

This clearly is my favorite solution because of the reduced coupling between authorization and resource servers.

Authorization server produces tokens without authorities (just a subject and scopes).
Resource-server retrieves authorities fetching an external source (like a DB) and then restrict it according to token scopes, if relevant.

No more tricks on authorities names, much simpler authorization-server implementation, smaller tokens, more flexibility on each resource-server.

Of course, this requires the resource-server to have more logic to retrieve those authorities from an external source (delegate to a `Repository`?)
and filter it according to scopes (if necessary as some resource-servers with single clients are frequently happy with all-or-nothing strategy).

<a name="alternateimpls"/>

## Alternate OAuth2 claims and authentication implementations

Following my path to building authentications a new way, I ended with new OAuth2 authentication implementations:
after all, claim-sets are just enough to manage all security once JWT are decoded or opaque tokens introspected.
 
Also, translating some of the OAuth2 specs to java helped me better grasp it.
I ended with classes I believe more handy than some spring-security ones.

### JWT and introspection claim-sets

As claim-sets **are** `Map<String, Object>`. Implementations in this lib extend `Map<String, Object>`.

It is handy for claim-sets to be mutable at build time, but once in an authentication it should be immutable.
I provide with MutableClaimSet, but both `JwtClaimSet` and `IntrospectionClaimSet` extend `ImmutableClaimSet`.

Also, some prefer to have an authorization-server produce tokens containing both user identity (`subject` standard claim) and grants (`authorities` private claim).
`WithAuthoritiesJwtClaimSet` and `WithAuthoritiesIntrospectionClaimSet` specializations serve that purpose.

### OAuth2ClaimSetAuthentication<T extends UnmodifiableClaimSet & Principal>

`Authentication` implementation which contains just one of above described claim-sets.
IMO easier to build, use and test than `JwtAuthenticationToken` and `OAuth2IntrospectionAuthenticationToken`.

Principal name is "subject" claim.

Authorities are derived from the claim-set by a `Converter`. 
Some implementations just read one of the claims (`WithAuthoritiesJwtClaimSet` and `WithAuthoritiesIntrospectionClaimSet` are designed to embed authorities)
but I also provide samples for converters querying a JPA repository to retrieve authorities granted to a "subject" (authorities **not** provided by the authorization-server).
