# Offline OTP React fixture attribution

These files are test-only and are not runtime dependencies or wheel package data.
They allow real React controlled-input acceptance without a CDN, Privy provider,
account, wallet, authentication endpoint, or real credential. Only the two
production UMD bundles are retained (about 140 KiB total); no SDK bundle,
source maps, node_modules, or package archives are added to the repository.

- `react-18.3.1.production.min.js` and `react-dom-18.3.1.production.min.js`
  are byte-identical npm `react` / `react-dom` 18.3.1 UMD distributions.
  Copyright (c) Facebook, Inc. and its affiliates. MIT license:
  `REACT-MIT-LICENSE.txt`. Bundle license notices are retained.
- `privy-public-code-handler.js` contains the **verbatim R input handler** from
  npm `@privy-io/react-auth` 3.49.0,
  `dist/cjs/AwaitingPasswordlessCodeScreen-BpE4_nMg.js` (Apache-2.0;
  `PRIVY-APACHE-2.0-LICENSE.txt`). The upstream package has no NOTICE file.
  **Modifications:** SDK imports, provider callbacks, rendering and network
  behavior are replaced with a minimal synthetic React mount and assertion-only
  completion callback. The source handler itself is unchanged. This fixture is
  not an unchanged/full Privy screen or proof of live Privy authentication.

`otp-react-provenance.json` records exact tarball URLs, npm SHA-512 integrity,
source members and React SHA-256 checksums. Acceptance verified tarball
integrities, React bundle byte equality and the handler's verbatim inclusion in
that pinned upstream package. Synthetic input names, type, digit pattern,
numeric mode and absence of maxlength are preserved during the fill.
