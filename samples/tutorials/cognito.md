# Configure Amazon Cognito
In this short article, we'll create a free account for Amazon Cognito, which is a cloud offer for an OIDC Provider, and configure it for tutorials.

First thing to do is registrering for a free account. If you don't have one, visit https://aws.amazon.com/fr/cognito/pricing/

Then, connect to https://us-east-2.console.aws.amazon.com and search for `cognito`:

![AWS console, browse to Cognito](https://github.com/ch4mpy/spring-addons/blob/master/.readme_resources/aws-console.png)

Click `Create user pool`:
1. For best user experience, you may enable `Federated Identity Providers` for Google, Facebook or both, but this requires you to have applications declared on their side. You can just ignore that if you haven't.

![Create user poll step 1](https://github.com/ch4mpy/spring-addons/blob/master/.readme_resources/create-user-pool-1.png)

2. As security requirements, to avoid any cost related to SMS, we'll opt for optional MFA with authenticator apps and recovery from email only.

![Create user poll step 2](https://github.com/ch4mpy/spring-addons/blob/master/.readme_resources/create-user-pool-2.png)

3. Keep all defaults for sign-up experience
4. For message delivery, we'll switch to `Send email with Cognito`:

![Create user poll step 4](https://github.com/ch4mpy/spring-addons/blob/master/.readme_resources/create-user-pool-4.png)

5. Enter Federated Identity providers credentials for those you picked at step 1 (if any)
6. Enter 
  - `spring-addons` as "User pool name"
  - choose a "Cognito domain" of your own
  - pick `Confidential client` as initial app type
  - enter `spring-addons-confidential` as app client name
  - pick `Generate a client secret`
  - enter `http://localhost:8080/login/oauth2/code/cognito-confidential-user` as Allowed callback URL
7. Create User Pool!

Now that the user pool is created, browse to its "App integration" tab
- note the User pool ID: the issuer to set in tutorials configuguration is `https://cognito-idp.{region}.amazonaws.com/{user-pool-id}`. As sample, with `us-east-2_xibdR1Rpv` as User pool ID, the issuer is `https://cognito-idp.us-east-2.amazonaws.com/us-east-2_xibdR1Rpv`
- note the "Cognito domain": it is the base path for the RP-Initiated Logout URL (`{cognito-domain}/logout`)
- scroll to the bottom of the page and click on the `spring-addons-confidential` app client to open its details
  - note the client-id
  - toggle the "Show client secret" and note it
  - edit the "Hosted UI" to add `http://localhost:8080/login/oauth2/code/cognito-confidential-user` in "Allowed callback URLs", as well as the following "Allowed sign-out URLs": 
    * `https://localhost:8080`
    * `https://localhost:8080/`
    * `https://localhost:8080/ui`
    * `https://localhost:8080/ui/`
    * `https://localhost:8080/ui/bulk-logout-idps`
    * `https://localhost:8080/ui/greet`
    * `http://localhost:8080`
    * `http://localhost:8080/`
    * `http://localhost:8080/ui`
    * `http://localhost:8080/ui/`
    * `http://localhost:8080/ui/bulk-logout-idps`
    * `http://localhost:8080/ui/greet`
-  Save changes

Next, from the "Users" tab of the "spring-addons" user pool, declare at least a user for yourself.

Last, Go to "Groups" tab to create a "NICE" group, click it once created and the details, click "Add a user to the group" and add aat least a user to this group.
 
You're all set to update tutorials configuration with your own Cognito instance & confidential client