# Introspection samples

Contains a sample authorization server and three resource-servers.
A single `@Controller` is used for all resource-servers and is defined in `showcase-common` library.

## Authorization-server

You'll need to change this one as it is made to serve three different set of introspection claim-set depending on client ID (aka login):
* "scope-authorites": puts authorities in "scope" claim.
  There just to satisfy spring-security default authentication-manager (bad feature IMO)
* "embedded-authorities": serves authorities in "authorities" claim.
  Authorities are filtered on scopes: if request "scope" is ["message", "userinfo"] then only authorities starting with "message:" or "userinfo:" are returned
* "jpa-authorities": no authority returned. Client should retrieve it from an external source (H2 database here)

You'll probably need at most one of those.

## Embedded-authorities resource-server

Resource server expecting authorities to contained in "authorities" claim. It connects to authorization-server using "embedded-authorities" client ID.
I chose to use an `AuthenticationManager` returning `OAuth2ClaimSetAuthentication<WithAuthoritiesIntrospectionClaimSet>` because I find it handier to use
but you could easily modify it to return `OAuth2IntrospectionAuthenticationToken`.

Good solution for an authorization-server with a small amount of clients.

## JPA-authorities resource-server

Resource server reads the "subject" claim and then retrieves authorities granted to it from a H2 database.

Entities and repository are defined in "showcase-common" library (shared with JWT sample).

As above, sample is based on `OAuth2ClaimSetAuthentication` but switching to `OAuth2IntrospectionAuthenticationToken` is mostly a mater of modifying the `AuthenticationManager`.

My favorite solution for multi-service information systems with single sing on (aka SSO) authorization-server:
* there no risk of colliding authority names as each service manages it on its own
* smaller tokens (authorities list can get very long if containing entries for many services)
* no coupling on authorities between authorization and resource servers

## Scope-authorities resource-server

Expects authorities to be embedded in "scope" claim.

There just to demo spring-security default `AuthenticationManager` as, 
IMO, it is bad practice to mix scope and authorities concepts.

To me, "authorities" should define what a user is allowed to do and "scope" what he restricts a client to,
meaning scopes should be used to filter user authorities.

