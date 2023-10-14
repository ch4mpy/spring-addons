# SPA Frontend

This is a demo SPA working with an OAuth2 BFF. It uses Angular, but **what we'll to to request the REST API has almost nothing specific to Angular and you should be able to port it to React or Vue without much effort.**

## Reminder about security mechanisms
All requests to the backend are proxied by the BFF and are authorized with sessions cookie.

Before forwarding the request to a REST API configured as an OAuth2 resource server, the BFF replaces this cookie with an `Authorization` header containing a `Bearer` access token in session.

Login and logout OAuth2 flow are handled by the BFF. This works with redirections (responses with status in the `3xx` range). To avoid CORS issues if we let Angular and the browser just follow thos 3xx, we hacked a bit the BFF:
- GET to `/login-options` answering with a `200` (ok) for possible URIs to initiate authorization_code flow
- POST to `/logout` answering with `201` (accepted) and a `Location` header with an URI to end the session on the authorization server too

We'll see how to query this two endpoints to login and logout users using the frontend.

## Changing the `baseHref`
The application is served with the `/ui/` context on the BFF (we need this prefix to identify that a request should be routed to the frontend). In Angular, this is done by adding `"baseHref": "/ui/",` to the `"architect"` -> `"build"` -> `"options"` of our project

## Defining a few constants for backend URIs
We'll first edit `app.module.ts` to import `HttpClientModule` and define the different URIs we'll use to build queries:
```typescript
export const gatewayUri = 'https://localhost:8080';
export const apiUri = `${gatewayUri}/bff/v1`;
export const greetingApiUri = `${apiUri}/greeting`;
export const usersApiUri = `${apiUri}/users`;
```

## User service
This is is the most interesting part as it contains all interactions related with the BFF itself: 
- `loginOptions()` is just performing a GET request to fetch the possible URIs we can call to initiate a login with `authorization_code` flow
- `login(loginUri: string)` initiates an `authorization_code` flow by setting the `window.location.href` to one of the URIs we got from `loginOptions`. This "exits" the Angular app and changes the requests origin to the host of the provided URI.
- `logout()` is performed in two steps:
  * first we send a POST request to the BFF `/logout` endpoint
  * then we extract the `Location` header which should contain an URI on the authorization server with all the required request params, and follow it the same way we did for login: by setting the `window.location.href`
- other methods expose information about current user state on the backend

Refer to `src/app/user.service.ts` for implementation details.

## UI for login, logout, and current user data display
We need to change the `AppComponent` to display a login button to user not yet identified, and a logout button as well as some data about themself to users who logged in.

This is dead simple as:
- all related to user identity is handled by the `UserService`
- there is absolutely nothing to do to authorize the request to the greeting API: the session cookie is silently added by the browser because we are sending the request to the BFF, and the BFF later replaces this cookie with an access token it stores in session, because it forwards the requests with on route configured with the `TokenRelay` filter

Refer to `src/app/app.module.ts` for implementation details.

## Running

Run `npm i` to install dependencies and then `ng serve` for a dev server without SSL.

If you have self-signed certificates for your development machine, you might copy or change one of the `bravo-ch4mp` or `mc-ch4mp` in `"architect"` -> `"serve"` -> `"configurations"` in `angular.json` and use `ng serve -c=my-conf` to start the dev server with SSL.

Of course a BFF (with a Greeting API behinf it) must be running on the host anf port you configured in the constants we defined with the Angular module.
