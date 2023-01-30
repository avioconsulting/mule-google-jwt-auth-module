# Mule Google JWT Auth Module Extension

## What?
This project contains utilities to generate a JWT and request an auth token from Google's authentication service

## Why?
The main reason for developing this project is to allow us to sidestep 3-legged OAuth built into Google connectors by generating a JWT and requesting an auth token from Google for use in authorizing HTTP requests.

## Changes
### 1.0.0
* Initial implementation
  - Basic implementation of the JWT generation code and request to Google Auth service

### 1.0.2
* Update for Mule 4.4 compatibilty

## Dependency
Add this dependency to your application pom.xml to use the module:
```xml
<groupId>com.avioconsulting.mule</groupId>
<artifactId>mule-google-jwt-auth-module</artifactId>
<version>1.0.2</version>
<classifier>mule-plugin</classifier>
```

## Using the Google JWT Auth Module

### Module configuration
Using the Google JWT Auth Module requires the creation of a global configuration containing information about the Google Service Account that will be used for any processors using it. The 'Issuer' field should contain the email address associated with the Service Account you wish to authorize and perform operations with. The Private Key and Private Key Id fields should come from fields with the same name in the JSON key you received after configuring the Service Account for OAuth.

### Using the 'Get google access token' Processor
The 'Get google access token' processor generates a JWT that it then sends to Google's auth service in exchange for an access token that it will then store on an object store. The user field is optional, and expects an email address for a user that the configured Service Account will impersonate for any operations performed with the received token. The scopes field is required and expects a comma separated list of all OAuth scopes the access token can be used for. Information on Google's OAuth scopes can be found [here](https://developers.google.com/identity/protocols/oauth2/scopes). The Object Store Config name field contains a reference to an Object Store global configuration that the processor will use to store the received access token.