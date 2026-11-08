# Dynamic login fixtures

The unmodified public MIT builds below execute real Vue/Vuetify component handlers
in isolated Chromium with synthetic credentials, including full Vuetify CSS.
They are test data only, not runtime dependencies or permission allowlists.

| File | Upstream source | SHA-256 |
| --- | --- | --- |
| vue-3.5.13.global.prod.js | https://unpkg.com/vue@3.5.13/dist/vue.global.prod.js | c459ba7cc8db65c982589fa5d64c7ff478877e8e5b0fd75683207cec6a4e89e8 |
| vuetify-3.7.6.min.js | https://unpkg.com/vuetify@3.7.6/dist/vuetify.min.js | 9bcc816fc5a63765c48ae145f5c40a31b11399b28deade4150ac0e4164df2138 |
| vuetify-3.7.6.min.css | https://unpkg.com/vuetify@3.7.6/dist/vuetify.min.css | 29afacdf65936874147946b5bb6aef89bba8f9edf516dbdf850dbe636b60736f |

Vue copyright: Yuxi (Evan) You and Vue contributors; see VUE-MIT-LICENSE.txt.
Vuetify copyright: Vuetify, LLC; see VUETIFY-MIT-LICENSE.txt. The license files
were fetched from the corresponding pinned package's LICENSE / LICENSE.md.

Coverage is bounded to the checked fixtures and guard contract, not all Vue or
Vuetify components/configurations. No production page, account or secret is used.
