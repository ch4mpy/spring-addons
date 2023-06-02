# Configure Auth0
In this short article, we'll create a free account for Auth0, which is a cloud offer for an OIDC Provider, and configure it for tutorials.

First thing to do is registrering for a free account. If you don't have one, visit https://auth0.com/ and "Sign up". Just choose `Other` as account type when you're prompted for it.

Once your account created, visit the [dashboard](https://manage.auth0.com/dashboard)
- select "Settings" from the left menu and under "API Authorization Settings", input `https://localhost:8080` as "Default Audience" and the following "Allowed Logout URLs":
```
https://localhost:8080,
https://localhost:8080/,
https://localhost:8080/ui,
https://localhost:8080/ui/,
https://localhost:8080/ui/bulk-logout-idps,
https://localhost:8080/ui/greet,
http://localhost:8080,
http://localhost:8080/,
http://localhost:8080/ui,
http://localhost:8080/ui/,
http://localhost:8080/ui/bulk-logout-idps,
http://localhost:8080/ui/greet,
https://localhost:7443,
https://localhost:7443/,
https://localhost:7443/ui,
https://localhost:7443/ui/,
https://localhost:7443/ui/bulk-logout-idps,
https://localhost:7443/ui/greet,
http://localhost:7443,
http://localhost:7443/,
http://localhost:7443/ui,
http://localhost:7443/ui/,
http://localhost:7443/ui/bulk-logout-idps,
http://localhost:7443/ui/greet
```
- select "Applications -> Applications" from the menu and click the "Default App"
  - enter `spring-addons-confidential` as name
  - select `Regular Web Application` as "Application Type"
  - enter `http://localhost:8080/login/oauth2/code/auth0-confidential-user, https://localhost:8080/login/oauth2/code/auth0-confidential-user, http://localhost:7443/login/oauth2/code/auth0-confidential-user, https://localhost:7443/login/oauth2/code/auth0-confidential-user` as "Allowed Callback URLs"
  - enter the same "Allowed logout URLs" as in general Settings
  - enter `http://localhost:8080, https://localhost:8080`, `http://localhost:7443, https://localhost:7443` as "Allowed Web Origins"
  - save changes

The issuer to configure in tutorials is `https://{Domain}/`. The "Domain" placeholder is to be retrieved from from the same application details screen, with Client ID and Client Secret. **Mind the trailing slash**.

![Application details](https://github.com/ch4mpy/spring-addons/blob/master/.readme_resources/auth0-application-details.png)

Next, create an action to enrich the access tokens with user data:
- browse to "Actions -> Flows -> Login"
- click "+ Add Action" and then "Build Custom"
- enter `Add user data to access and ID tokens` as "Name" and keep "Login / Post Login" as well as default Runtime version
- script body:
```typescript
exports.onExecutePostLogin = async (event, api) => {
  const namespace = 'https://c4-soft.com';
  const user = Object.assign({}, event.user);
  user.roles = event.authorization?.roles || [];
  api.accessToken.setCustomClaim(`${namespace}/user`, user);
  api.idToken.setCustomClaim(`${namespace}/user`, user);
  return; // success
};
```

From the left menu, select "User Management -> Users" and add at least a user for yourself.

From the left menu, click "Roles" and add a `NICE` role

From the left menu, click "Users", open one of the users details, browse to "Roles" tab, click "+ ADD ROLE TO USER", and assign the `NICE` role

You're all set to update tutorials configuration with your own Auth0 instance & confidential client