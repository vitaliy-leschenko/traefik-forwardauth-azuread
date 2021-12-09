# What is it?
This is demo how to use `forwardauth` middleware of `traefik`.
You can find more details about it on [official traefik docs](https://doc.traefik.io/traefik/middlewares/http/forwardauth/)

# How to use it (in k8s)?
1. register an app in Azure Active Directory to obtain `ClientId`, `ClientSecret`, `TenantId`
2. build docker image `src/TraefikAuthAAD/Dockerfile` and publish it to a registry
3. create a deploy and make sure that you override these environment variables:
  - JwtSigningKey="-- required: put your signing key --"
  - AzureAD__GroupId="-- optional: put id of group to restrict list of users that have access --"
  - AzureAD__ClientId="{clientId}"
  - AzureAD__ClientSecret="{clientSecret}"
  - AzureAD__AuthorizeEndpoint="https://login.microsoftonline.com/{tenantid}/oauth2/v2.0/authorize"
  - AzureAD__TokenEndpoint="https://login.microsoftonline.com/{tenantid}/oauth2/v2.0/token"
4. create a service for the deploy
5. create a traefik middleware object:
  ```
  apiVersion: traefik.containo.us/v1alpha1
  kind: Middleware
  metadata:
    name: auth
  spec:
    forwardAuth:
      address: http://{service name or ip}/auth
      trustForwardHeader: true  
  ```
6. use the middleware in your ingress objects
