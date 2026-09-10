from pathlib import Path

import pytest

from nigerian_secrets.scanner import scan


BASE = "sk_test_abcdefghijklmnopqrstuvwxyz123456"


def _cases() -> list[tuple[str, str, bool]]:
    cases: list[tuple[str, str, bool]] = []
    for index in range(120):
        mode = index % 12
        if mode == 0:
            text = f'PAYSTACK_SECRET = "{BASE}"'
            expected = True
        elif mode == 1:
            text = f'PAYSTACK_SECRET= "{BASE}"'
            expected = True
        elif mode == 2:
            text = f'PAYSTACK_SECRET : "{BASE}"'
            expected = True
        elif mode == 3:
            text = f'PAYSTACK_SECRET = "{BASE[:10]}\\n{BASE[10:]}"'
            expected = False
        elif mode == 4:
            text = f'PAYSTACK_SECRET = "{BASE.replace("_", "\\u005f")}"'
            expected = False
        elif mode == 5:
            text = f'PAYSTACK_SECRET = "{BASE.upper()}"'
            expected = False
        elif mode == 6:
            text = f'PAYSTACK_SECRET = "{BASE}" # punctuation'
            expected = True
        elif mode == 7:
            text = f'paystack API_SECRET = "{BASE}"'
            expected = True
        elif mode == 8:
            encoded = BASE.replace("_", "%5F")
            text = f'PAYSTACK_SECRET = "https%3A%2F%2Fexample.invalid%2F{encoded}"'
            expected = False
        elif mode == 9:
            text = f'PAYSTACK_SECRET = "{BASE[:16]}" + "{BASE[16:]}"'
            expected = False
        elif mode == 10:
            text = f'PAYSTACK_SECRET = "{BASE[:18]}"'
            expected = False
        else:
            text = f'PAYSTACK_SECRET = "not-a-secret-{index}"'
            expected = False
        cases.append((f"case-{index:03d}", text, expected))
    return cases


@pytest.mark.parametrize("case_id,text,expected", _cases())
def test_adversarial_inputs_are_bounded_and_never_leak(tmp_path: Path, case_id: str, text: str, expected: bool):
    sample = tmp_path / f"{case_id}.txt"
    sample.write_text(text, encoding="utf-8")
    findings = scan(tmp_path)
    detected = bool(findings)
    assert detected is expected
    assert BASE not in repr(findings)
