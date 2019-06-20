# Samples
Authorization and resource servers to illustrate various ways to use OAuth2ClaimSetAuthentication:
 * JWT or opaque (introspected) tokens
 * Authorities embedded in token claims by authorization-server or managed by resource-server
 
I provide with end-to-end test project which packages the two others.
Test cases start authorization and resource servers with different profiles and uses a `TestRestClient` to demo tokens retrieval and protected resources access.
 
## Choosing token format
By default, user-agent, authorization-server and resource-server exchange opaque Bearer tokens
and resource-server retrieves claims from authorization-server `/introspect` end-point.

You can switch to JWT by activating **jwt** profile on **both** applications.
Resource-server will then read claims from the token itself (`/introspect` end-point not exposed anymore).

## Choosing authorities lookup mode
By default, the resource-server expects authorities to be provided by authorization server in `authorities` claim
(either inside the JWT or from introspection end-point).

By activating the **jpa** profile, you can switch to a database lookup: resource server then retrieves authorities by "subject" from a H2 database.
Initialization script is the regular one for spring-boot: data.sql in resources folder.

## Configured data:
You might open authorization-server and resource-server configuration files to confirm values below.

Authorization-server listening on port `8080`.

Token end-point is `https://localhost:8080/oauth/token`.

Two authorization-server clients:
 * `user-agent` / `secret`: to get access and refresh tokens with `showcase` scope using `password` grant flow (see below for users credentials)
   using your favorite user-agent (Postman, web-browser, ...)
 * `showcase-resource-server` / `secret`: to query claims with `showcase` scope at `/introspect` end-point. Resource-server uses it.
   You can use it too to reproduce introspection query (with Postman for instance)

Three users:
 * `user` / `password`: has `"ROLE_USER"` on both authorization-server and resource-server H2 database
 * `admin` / `password`: has `["ROLE_USER", "showcase:AUTHORIZED_PERSONEL"]` on authorization-server and `["ROLE_USER", "ROLE_ADMIN"]` in H2
 * `jpa` / ` password`: no authority on authorization-server and `["ROLE_USER", "showcase:AUTHORIZED_PERSONEL"]` in H2

Resource-server listening on port `8090`.

Three resource end-points
 * `https://localhost:8090/greeting` accessible to any authenticated user (valid bearer token in authorization header), displays token subject
 * `https://localhost:8090/restricted/greeting` accessible only to users granted with `showcase:AUTHORIZED_PERSONEL` authority
 * `https://localhost:8090/claims` accessible to any authenticated user, displays token claims 
   (depending on the profile, either embedded in JWT or from introspection end-point)
 
So, depending on **jpa** profile being active or not on resource-server, you will access `https://localhost:8090/restricted/greeting`
with either `jpa` or `admin` user only (`showcase:AUTHORIZED_PERSONEL` is required).

Beware that if using **jpa** profile, user authorities on resource-server are likely to diverge from token `authorities` claim (if any)
   