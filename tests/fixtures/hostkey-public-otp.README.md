# Public OTP fixture provenance

Verbatim component extracted by the parent worker from the public bundle:
https://hostkey.ru/minify/default-a7f53408f947e7042d6adeeadb837fb9.js

Only the public OTP component is retained. Synthetic markup supplies the observed
hidden canonical `smscode` input with min=6; the component itself creates every
untouched digit and attaches its original handlers. The fixture stubs `o`,
`HKSEC.validate2fa` and jQuery's login-button click with a counter, never a real
login or network submission. Assertions cover canonical aggregation, focus,
filled state, disabled final digits and exactly one delayed site click.
