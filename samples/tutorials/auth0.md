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

Next, create a rule to enrich the access tokens with user data:
- browse to "Auth Pipeline -> Rules"
- click "+ Create" and then "<> Empty rule"
- enter `Add user data to access and ID tokens` as "Name"
- set the following rule script:
```typescript
function addUserData(user, context, callback) {
  context.accessToken['https://c4-soft.com/spring-addons'] = user;
  context.idToken['https://c4-soft.com/spring-addons'] = user;
  return callback(null, user, context);
}
```
![Rule to add user data to access tokens](https://github.com/ch4mpy/spring-addons/blob/master/.readme_resources/auth0-user-data-rule.png)

From the left menu, select "User Management -> Users" and add at least a user for yourself.

Select "Extensions" from the left menu and:
- install `Auth0 Authorization`
- click "Auth0 Authorization" to navigate to "Authorization Extension" details
- click "Go To Configuration"
- enable `Groups`, `Roles` and `Permissions` toggles
- click "ROTATE"
- click "PUBLISH RULE"
- from the left menu, click "Roles" and add a `NICE` role
- from the left menu, click "Users", open one of the users details, browse to "Roles" tab, click "+ ADD ROLE TO USER", and assign the `NICE` role

You're all set to update tutorials configuration with your own Auth0 instance & confidential client