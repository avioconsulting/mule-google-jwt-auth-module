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
