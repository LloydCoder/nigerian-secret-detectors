from __future__ import annotations

from dataclasses import dataclass
import re

from .providers import PROVIDERS


@dataclass(frozen=True)
class Rule:
    id: str
    provider: str
    category: str
    severity: str
    pattern: re.Pattern[str]
    keywords: tuple[str, ...]
    message: str


BASE_RULES: tuple[Rule, ...] = (
    Rule(
        "paystack-secret-key", "paystack", "fintech", "critical",
        re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9_-]{20,}\b"),
        ("paystack", "sk_live_", "sk_test_"),
        "Paystack secret key pattern detected.",
    ),
    Rule(
        "flutterwave-secret-key", "flutterwave", "fintech", "critical",
        re.compile(r"\bFLWSECK[_-][A-Za-z0-9_-]{20,}\b", re.I),
        ("flutterwave", "flwseck", "rave"),
        "Flutterwave secret key pattern detected.",
    ),
    Rule(
        "monnify-secret-key", "monnify", "fintech", "critical",
        re.compile(r"\b(?:MK_TEST_|MK_LIVE_)[A-Za-z0-9_-]{16,}\b", re.I),
        ("monnify", "mk_test_", "mk_live_"),
        "Monnify secret credential pattern detected.",
    ),
    Rule(
        "korapay-secret-key", "korapay", "fintech", "critical",
        re.compile(r"\b(?:sk_(?:live|test)_|pk_(?:live|test)_)[A-Za-z0-9_-]{20,}\b", re.I),
        ("korapay", "kora pay"),
        "KoraPay credential pattern detected; provider context is required for high confidence.",
    ),
    Rule(
        "seerbit-secret-key", "seerbit", "fintech", "high",
        re.compile(r"\b(?:sk|secret)[_-][A-Za-z0-9_-]{24,}\b", re.I),
        ("seerbit", "publickey", "privatekey", "secretkey"),
        "SeerBit credential-like value detected in provider context.",
    ),
    Rule(
        "interswitch-mac-key", "interswitch", "fintech", "critical",
        re.compile(r"\b(?:macKey|mackey)\s*[:=]\s*[\"']?([A-Fa-f0-9]{64})[\"']?"),
        ("interswitch", "webpay", "mackey", "mac_key"),
        "Interswitch WebPAY MAC key pattern detected.",
    ),
    Rule(
        "remita-secret-context", "remita", "fintech", "high",
        re.compile(r"\b(?:api[_-]?key|api[_-]?hash|secret[_-]?key)\s*[:=]\s*[\"']([A-Za-z0-9+/=_-]{24,})[\"']", re.I),
        ("remita", "merchantid", "merchant_id", "rrr"),
        "Remita credential-like value detected in provider context.",
    ),
    Rule(
        "opay-secret-context", "opay", "fintech", "high",
        re.compile(r"\b(?:secret|api[_-]?key|private[_-]?key|access[_-]?token)\s*[:=]\s*[\"']([A-Za-z0-9+/=_-]{24,})[\"']", re.I),
        ("opay", "o-pay"),
        "OPay credential-like value detected in provider context.",
    ),
    Rule(
        "palmpay-secret-context", "palmpay", "fintech", "high",
        re.compile(r"\b(?:secret|api[_-]?key|private[_-]?key|access[_-]?token)\s*[:=]\s*[\"']([A-Za-z0-9+/=_-]{24,})[\"']", re.I),
        ("palmpay", "palm pay", "palm-pay"),
        "PalmPay credential-like value detected in provider context.",
    ),
    Rule(
        "generic-private-key", "crypto", "cryptographic", "critical",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
        (),
        "Private key material detected.",
    ),
    Rule(
        "nigerian-provider-jwt", "nigerian-fintech", "token", "high",
        re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        ("paystack", "flutterwave", "remita", "interswitch", "monnify", "korapay", "opay", "palmpay", "api_token", "access_token"),
        "JWT-like token detected in Nigerian financial provider context.",
    ),
)

_CONTEXT_RULES: tuple[Rule, ...] = tuple(
    Rule(
        f"{provider.id}-credential-context",
        provider.id,
        provider.category,
        "high",
        re.compile(
            r"\b(?:api[_-]?key|api[_-]?secret|client[_-]?secret|secret[_-]?key|access[_-]?token|private[_-]?key)"
            r"\s*[:=]\s*[\"']([A-Za-z0-9+/=_-]{24,})[\"']",
            re.I,
        ),
        tuple(provider.aliases),
        f"{provider.name} credential-like value detected in provider context.",
    )
    for provider in PROVIDERS
    if provider.id not in {"paystack", "flutterwave", "monnify", "korapay", "seerbit", "interswitch", "remita", "opay", "palmpay"}
)

RULES: tuple[Rule, ...] = BASE_RULES + _CONTEXT_RULES
