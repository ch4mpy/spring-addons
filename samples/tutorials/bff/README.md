# Implementing the **B**ackend **F**or **F**rontend pattern with `spring-cloud-gateway`

A [project applying the exact same pattern](https://github.com/ch4mpy/quiz) is deployed to a publicly available K8s cluster managed by [OVH](https://www.ovhcloud.com/fr/public-cloud/kubernetes/)): [https://quiz.c4-soft.com/ui/](https://quiz.c4-soft.com/ui/)

## 1. Introduction

What we built here is a SPA frontend talking to an OAuth2 resource server by the intermediate of an OAuth2 BFF. The aim is to follow the latest [Spring Security team recommandations](https://github.com/spring-projects/spring-authorization-server/issues/297#issue-896744390) and use a server-side "confidential" OAuth2 client instead of configuring the SPA as a "public" OAuth2 client.

The frontend uses Angular, but **what we'll to to request the REST API has almost nothing specific to that framework and you should be able to port it to React or Vue without much effort.**


### 1.1. The **B**ackend **F**or **F**rontend Pattern
There isn't a unique definition for BFF and the Security features it should implement could change from an article you read to another. What we call BFF here is:
- a server-side application
- authorizing requests from frontend with sessions
- configured as an OAuth2 client with login (at least one client configured with `authorization_code` flow)
- storing OAuth2 tokens in session
- replacing session cookie with an authorization header containing the bearer access token in session before forwarding a request from the frontend to a REST API

In this configuration, the frontend is not OAuth2 at all and never access tokens. The tokens are kept safe on the server.

As BFF, we will use `spring-cloud-gateway` with `TokenRelay` filter and `spring-boot-starter-oauth2-client`.

### 1.2. Quick note on CORS
When serving both the UI (Angular app) and the REST API(s) through a reverse-proxy, from the browser perspective, all requests have the same origin, which removes the need for any CORS configuration.

But the main reason why we need it here is that Spring session cookies are flagged with `SameSite=Lax` by default. So, for the browser to send session cookie with Angular requests to the BFF (and give the `TokenRelay` filter an opportunity to do its job), Angular app & BFF should have the same origin (the reverse-proxy).

Here we use the spring-cloud-gateway as BFF (`oauth2Login()` and `TokenRelay`) and also as reverse-proxy for the UI (we serve Angular assets through the gateway), but you can choose to put a standalone reverse-proxy in front of the BFF instead. This reverse-proxy really doesn't have to be a spring-cloud-gateway instance: it can be a nginx, a K8s ingress or whatever.

### 1.3. Authentication sequence
When user authentication is needed:
0. the SPA calls the gateway to get the options it supports to authenticate users (this happens at any moment, preferably before the user attempts a login)
1. the SPA "exits" by setting `window.location.href` with an URI provided at step 0. (`/oauth2/authorization/{registration-id} on the BFF)
2. the BFF redirects the user to the authorization-server (specifying a callback URL where it expects to receive an authorization code in return)
3. the user authenticates
4. the authorization-server redirects the user back to the BFF with an authorization code
5. the BFF fetches OAuth2 tokens from the authorization-server and stores it in session
6. the BFF redirects the user back to the browser app at an URI specified at step 1. ("re-enters" the SPA)

The user session is now "authorized", and the BFF can replace session cookie with a `Bearer` access token before forwarding requests from frontend to resource servers.

## 2. Modules
This repo contains two main folders: 
- `backend` with a Maven multi-module project with everything related to Spring. It is itself split into two sub-modules:
  * `official` depending only on `spring-boot-starter-oauth2-client` and `spring-boot-starter-oauth2-resource-server`
  * `with-c4-soft` which uses `spring-addons-starter-oidc` in addition to "official" starters. We'll see that this greatly reduces the amount of Java code and simplifies security configuration.
- `frontend` with a very simple Angular application authenticating users on the BFF and querying the REST API.

Please refer to the README inside each of this folders for more instructions.

## 3. Prerequisites
We assume that [tutorials main README prerequisites section](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials#prerequisites) has been followed and that you have a local Keycloak instance runing on localhost with SSL.
