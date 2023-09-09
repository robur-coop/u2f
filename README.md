## U2F - Universal Second Factor

U2F is a
[FIDO standard](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/)
for two-factor authentication using specialized USB or NFC devices, similar
to smart cards. Challenge-response authentication with the device using public
key cryptography is supported by various applications, i.e. web browsers and
ssh.

This package implements the server side of the U2F protocol: requesting and
finalizing both a registration and an authentication via json messages exchanged
between the browser and the server. The implementation does not keep any state,
instead the user of the API needs to persist the state (challenges, keyHandle,
public keys, ...). A basic demonstration server is provided (`bin/u2f_demo`),
running at [u2f-demo.robur.coop](https://u2f-demo.robur.coop).

## Documentation

[API documentation](https://robur-coop.github.io/u2f/doc) is available online.

## Installation

`opam install u2f` will install this library.
