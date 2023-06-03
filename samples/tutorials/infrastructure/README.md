# Docker configuration for tutorials
This directory contains a docker compose (V3) file that will start keycloak without installing it locally.

## Prerequisites
1. A recent version of docker that supports the new compose file format (V3)
2. A self-signed SSL certificate.  See [this github reposiotry](https://github.com/ch4mpy/self-signed-certificate-generation) for tutorial on creating one for your development environment.

## Changes you have to make locally
1. Create a subdirectory `samples/tutorials/infrastructure/keycloak`
2. Add the following files to this directory
   1. The self-signed SSL certificate for your development environment re-named to `self_signed.crt`
   2. The private key associated with the certificate for for your development environment re-named to `self_signed_key.pem`

The files in this directory (`samples/tutorials/infrastructure/keycloak`) are needed to make keycloak work from docker compose.  However, they contain sensitive information that should never be committed to a repository.
The project's `.gitignore` should contain the following line
```
/samples/tutorials/infrastructure/keycloak/
```

## Starting keycloak
1. Open a terminal
2. Change directory to `samples/tutorials/infrastructure`
3. Enter the command `docker compose up --detach`
4. Open a browser and navigate to the [running keycloak instance](https://localhost:8443/admin)
5. Enter user `admin` with password `admin1`
6. Continue configuring keycloak with the README.md in tutorial directory in the Prerequisites section

## Stopping keycloak
1. Open a terminal (or use the one already open)
2. Change directory to `samples/tutorials/infrastructure`
3. Enter the command `docker compose down`