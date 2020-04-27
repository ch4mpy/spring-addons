# spring-security OAuth2 addons

What I propose here are tools to extend spring-security for OAuth2.

1. [Abstract](#abstract)<br/>
2. [Scopes & Authorities](#scopes-authorities)<br/>
3. [`OidcId`](#oidcid)<br/>
4. [`Resource-server configuration helpers for Keycloak authorization-server`](#keycloak)<br/>

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

## What's in there ?

Some extensions to Spring OAuth2 that could be of use at runtime (not solely tests) such as:
 * new `Authentication` implementations (`OidcIdAuthenticationToken` for instance)
 * builders for `Jwt`, `BearerTokenAuthentication`, ...
 * base classes for Keycloak authentication configuration

There are reasons to use other `Authentication` implementations than what is provided by Spring for OAuth2 (`JwtAuthenticationToken` & `BearerTokenAuthentication`):
 * scopes (what resource owner allows a client to do in his name) are not authorities (what a resource owner is allowed to on a resource-server)
 * getting just an `Object` when accessing principal or credentials
 * `OAuth2AccessToken` is a rather broken implementation

It is likely that the implementations I propose here do not meet your needs. Hopefully, it's actually quite easy to develop your own and this lib sources should provide some inspiration.

<a name="scopes-authorities"/>

## Scopes and authorites

### Scopes
As explained in introduction, IMO scopes should be packs of permissions for an end-user to control the access he grants different clients with to resources he owns.

Lets illustrate how different the relation between scopes and authorities can be with two extreme samples:
 * social-network resource-server with many "untrusted" clients: 
   almost a scope per authority for the user to define precisely what he allows each client can access (age, gender, phone, friends, etc.)
 * resource server with a single trusted client (back-end for mobile or Angular application for instance): no scope at all required. 
   If user authenticates with the client, then full access is granted (in the user's limits, off course)
   
### Authorities
There is no requirement for authorities to be contained in token claims.
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
is to use resource-server name as authorities prefix.

### Authorities retrieved from an external source with token subject

This clearly is my favorite solution because of the reduced coupling between authorization and resource servers.

Authorization-server tokens are used to retrieve end-user ID.
Resource-server retrieves authorities fetching an external source (like a DB) and then restrict it according to token scopes, if relevant.

No more tricks on authorities names, much simpler authorization-server implementation, smaller tokens, more flexibility on each resource-server.

Of course, this requires the resource-server to have more logic to retrieve those authorities from an external source (delegate to a `Repository`?)
and filter it according to scopes (if necessary as some resource-servers with single clients are frequently happy with all-or-nothing strategy).

<a name="oidcid"/>

## `OidcId`

`OidcId` is a convenient OpenId token implementation (implemnts both `IdTokenClaimAccessor` and `StandardClaimAccessor`). It comes with a builder and a dedicated `AbstractAuthenticationToken`: `OidcIdAuthenticationToken`

<a name="keycloak"/>

## `Keycloak`

`KeycloakEmbeddedAuthoritiesConverter` extracts authorities embedded in `realm_access`.`roles` claim

`KeycloakJwtAuthenticationTokenConverter` turns a `Jwt` into a `JwtAuthenticationToken` (close to what Spring boot does by default)

`KeycloakOidcIdAuthenticationTokenConverter` turns a `Jwt` into a `OidcIdAuthenticationToken` (provides with a much easier to use `Authentication` implementation than `JwtAuthenticationToken`)