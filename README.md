# SOAP Header Generator

This utility project can be used to generate the SOAP Header for JAX-WS requests with WSSE 
Security PasswordDigest standard.

## Requirements

For building and running the application you need:

- [JDK 11](https://www.oracle.com/java/technologies/downloads/#java11-mac)
- [Maven 3](https://maven.apache.org)

## To Build and Package the application

```shell
mvn clean install
```

## Running the application locally

There are several ways to run this Java application on your local machine. One way is to execute
the `main` method in the `com.digest.WssePasswordDigestGenerator` class from your IDE.

Alternatively you can use the java -jar command.

```shell
java -jar target/password-digest-generator-1.0-shaded.jar
```
