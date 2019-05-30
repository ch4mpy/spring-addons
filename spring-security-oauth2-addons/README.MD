# spring-security addons
What I propose here are tools to extend spring-security.
For now, this is limited to OAuth2, but could grow.

1. [Abstract](#abstract)<br/>
2. [Authorities in an OAuth2 multi service application](#multiserviceapp)<br/>
3. [Alternate OAuth2 claims and authentication implementations](#alternateimpls)<br/>

<a name="abstract"/>

## Abstract
I initiated this lib to start working with Spring 5 OAuth2 implementation in multi-service application.
At time I write this, in Spring 5 OAuth2, authorities are embedded in "scope" (or "scp") claim and prefixed with "SCOPE_".
There are ways (rather complicated) to work arround those limitations for JWT authentication but not really for introspection ones.

<a name="multiserviceapp"/>

## Authorities in an OAuth2 multi service application
I thought of two different ways to associate authorites with a token in a multi service application:

1. the authorization server feeds an "authorities" claim associated to the token (in the JWT or available at the introspection endpoint)
2. the resource server retrieves authorities granted to the token subject (end user ID, client name, ...) from an other source than authorization server

First solution makes it very simple for resource-servers to build authentications as both name and authorities are contained in the token claims but:
 * updating authorities definition for a service requires modifying the authorities service (at least its database) which can be an issue when maintained by another team
 * authorities names are likely to collide between services without a carefull namesapce separation

Using an authorization service rather than a token converter, allows to build OAuth2 authentications the same way,
authorities being embedded in the token or stored somewhere like a SGBD.
In first case, the service implementation could delegate to a converter and in the second to a JPA repository.

Also, to mitigate authorities names collisions in token embedded authorities, scopes can be used to
 * define authorities namespaces
 * determine which authorities to feed the token claim with.
 
For instance, a client needing access to a messaging service would request authentication with "message" scope.
If OAuth2 authorization is granted, the Jwt or Introspection authentication should have "message" scope-claim and 
also an authorities claim with values such as "message:read message:write". 
Authorities in "message" resource-server `Authentication` would then be {"read", "write"}

<a name="alternateimpls"/>

## Alternate OAuth2 claims and authentication implementations
Following my path to building authentications a new way, I ended with new OAuth2 authentication implementations:
claim-sets are just enough to manage all security once tokens are decoded or introspected
 
Also, translating the OAuth2 specs to java helped me better grasp it. I also provided me we classes I believemore handy than some spring-security ones.