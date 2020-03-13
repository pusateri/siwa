# Sign In With Apple JSON Web Token validator library

When using Sign In with Apple on an iOS/iPadOS/macOS device, the client receives an identity token and user token to send to a web/cloud server for validation. The identity token is in the form of a base64 encoded, signed, JSON Web Token (JWT).

This library can be used on the server side to validate the identity token with Apple's servers. An identity token is usually only valid for about 5 minutes.

For testing, it can be valuable to save an identity token for longer than 5 minutes and validate it except for the expiry time. A flag is provided for this purpose when calling the validator.

Apple also provides a mechanism for the server to re-validate the user periodically (but not more than once per day). A future version of this library will add this functionality.
