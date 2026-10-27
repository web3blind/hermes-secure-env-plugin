"""Closed fixed-format contract; all card material is synthetic local fixture data."""

import copy
import pytest
from secure_env_ingress.exact_card import validate_spec, values_for
from exact_card_helpers import spec, SECRET


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown",
        "purpose",
        "version",
        "secret",
        "js",
        "selector",
        "format",
        "role",
        "frame",
        "duplicate",
        "missing",
        "expiry_conflict",
        "bad_split",
        "bool",
    ],
)
def test_closed_card_contract(mutation):
    s = spec()
    if mutation == "unknown":
        s["unknown"] = 1
    elif mutation == "purpose":
        s["purpose"] = "transient_code"
    elif mutation == "version":
        s["version"] = 2
    elif mutation == "secret":
        s["fields"][0]["value"] = "synthetic"
    elif mutation == "js":
        s["fields"][0]["formatter"] = "v=>v"
    elif mutation == "selector":
        s["fields"][0]["selector"] = "input:has(+input)"
    elif mutation == "format":
        s["fields"][0]["format"] = "arbitrary"
    elif mutation == "role":
        s["fields"][0]["role"] = "password"
    elif mutation == "frame":
        s["fields"][0]["frame"] = "https://wrong.test"
    elif mutation == "duplicate":
        s["fields"][1] = copy.deepcopy(s["fields"][0])
    elif mutation == "missing":
        s["fields"].pop()
    elif mutation == "expiry_conflict":
        s["fields"].append(dict(role="month", selector="#m", frame="top", format="MM"))
    elif mutation == "bad_split":
        s = spec(split=[4, 4])
    else:
        s["version"] = True
    with pytest.raises(ValueError):
        validate_spec(s, "target")


def test_canonical_copy():
    s = spec()
    v = validate_spec(s, "target")
    s["fields"][0]["selector"] = "#other"
    assert v["fields"][0]["selector"] == "#pan"


@pytest.mark.parametrize(
    "fmt,value",
    [
        ("MM/YY", "12/31"),
        ("MM/YYYY", "12/2031"),
        ("MMYY", "1231"),
        ("MMYYYY", "122031"),
        ("MM-YY", "12-31"),
        ("MM-YYYY", "12-2031"),
    ],
)
def test_expiry_formats(fmt, value):
    s = validate_spec(spec(expiry=fmt), "target")
    assert values_for(s, SECRET)[2] == value


@pytest.mark.parametrize("length", range(12, 20))
def test_pan_lengths(length):
    base = "4242424242424242424"[: length - 1]

    def luhn(s):
        return (
            sum(
                d if i % 2 == 0 else 2 * d - 9 if d >= 5 else 2 * d
                for i, d in enumerate(map(int, s[::-1]))
            )
            % 10
        )

    pan = next(base + str(d) for d in range(10) if luhn(base + str(d)) == 0)
    s = validate_spec(spec(split=[4, length - 4]), "target")
    vals = values_for(s, dict(SECRET, card_number=pan))
    assert vals[0] + vals[1] == pan


@pytest.mark.parametrize(
    "key,value",
    [
        ("card_number", "4242424242424242\n"),
        ("cardholder_name", "Fake\nHolder"),
        ("exp_year", "2031\n"),
        ("cvc", "123\n"),
    ],
)
def test_linebreak_refused(key, value):
    with pytest.raises(ValueError):
        values_for(validate_spec(spec(), "target"), dict(SECRET, **{key: value}))


def test_split_length_mismatch():
    s = validate_spec(spec(split=[4, 4, 4, 3]), "target")
    with pytest.raises(ValueError):
        values_for(s, SECRET)
