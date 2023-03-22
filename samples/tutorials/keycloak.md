# Configure a Local Keycloak Instance
If you do not have a SSL certificate yet, refer to instructions in [this repo](https://github.com/ch4mpy/self-signed-certificate-generation) to generate one and add it to bot your JRE cacerts file and your OS trusted root certificates.

Here is sample configuration for [Keycloak power by Quarkus](https://www.keycloak.org/downloads):
```
hostname=localhost

http-enabled=true
http-port=8442
https-key-store-file=C:/Users/machin/.ssh/localhost_self_signed.jks
https-key-store-password=change-me
https-port=8443
```
Then start Keycloak with `start-dev` command line argument:
- on Windows: `C:\keycloak-install-dir\bin\kc.bat start-dev`
- on Linux / Mac: `/keycloak-install-dir/bin/kc.sh start-dev`

This will make Keycloak available on both https://localhost:8442 and https://localhost:8443

Browse to https://localhost:8443, create an admin account, and browse to the admin console

First go to "Clients" and click "Create Client" to add a `spring-addons-confidential` client:
- enable `Client authentication`, `Standard flow` and `Service accounts roles`
- set `http://localhost:8080/*`, `https://localhost:8080/*`, `http://localhost:7443/*` and `https://localhost:7443/*` as "Valid redirect URIs"
- set `+` for both "Valid post logout redirect URIs" and "Web origins"

![confidential client creation screen-shot](https://github.com/ch4mpy/spring-addons/blob/master/.readme_resources/keycloak-confidential.png)

Once the client declared, open its details to 
- set `https://localhost:8080/backchannel_logout` as "Backchannel logout URL"
- enable `Backchannel logout revoke offline sessions`

The client secret to update tutorials configuration is available from credentials tab of client details.

Tutorials expect some users to be granted with `NICE` authority. This will require them to be granted with `NICE` "realm role" in Keycloak. An alternative would be to define this role for `spring-addons-public` and enable client roles mapper (clients => spring-addons-public => Client scopes => spring-addons-public-dedicated => Add predefined mapper)

Lets create two users for our live tests:
- `Brice` with `NICE` role granted
- `Igor` without `NICE` role

Don't forget to set a password for those users.

You're all set to update tutorials configuration with your own Keycloak local instance & confidential client.