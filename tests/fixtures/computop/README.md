# Public asset provenance and fixture boundary

The CSS and SVG bytes are copied without edits from the parent's query-free
public fetches. `manifest.json` records their exact URLs and SHA256 hashes,
including two additionally fetched public WOFF2 fonts used by this fixture.
`topology.json` is the parent's secret-free wrapper/label/input/image capture.

`computop_fixture.py` reconstructs that topology (including required, placeholder,
maxlength, autocomplete, sibling labels/asterisk children and DIV+IMG brands).
The capture omitted `for` from its attribute allowlist; explicit associations are
reconstructed for the corresponding sibling inputs. A synthetic SSLForm, hidden
KKName/month/year controls, unchecked storage/open-invoice checkbox and Pay
button are added. No provider CSS is invented, patched or inserted to satisfy
runtime guard predicates. Registered tests relocate public asset URLs onto the
synthetic child origin to preserve same-origin CSSOM readability; bytes remain
identical and no requests reach the public provider.

Handlers reproduce the saved public `accounts-unified-main.js` valid VISA branch:
se() hides all brands, ae() displays the chosen brand flex, KKName.value is set,
and PAN formatting uses single ASCII group spaces. Focus/blur masking hooks are
retained for the data-pkn negative cases. This is not the entire provider bundle,
jQuery/Maskito runtime, server, or a live payment acceptance test.

The captured viewport is 576x334, brand dimensions 45x20, top14/right15 and PAN
right-padding70. The fixture retains natural grid layout rather than forcing
captured column widths with convenient CSS. Sanitized surrounding content can
change min-content column distribution; safety is tested against the actual
computed padding reserve and unchanged protected rectangles, not a faked width.
