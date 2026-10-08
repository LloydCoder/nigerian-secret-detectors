from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

DetectionType = Literal["provider-specific", "provider-context", "generic", "cryptographic", "token", "heuristic"]


@dataclass(frozen=True)
class Provider:
    id: str
    name: str
    category: str
    aliases: tuple[str, ...] = ()
    detection_type: DetectionType = "provider-context"


# Provider names are metadata/context signals unless a dedicated rule establishes
# a provider-specific credential grammar. This prevents generic context rules from
# being represented as native token recognition.
PROVIDERS: tuple[Provider, ...] = (
    Provider("paystack", "Paystack", "payments", ("paystack",), "provider-specific"),
    Provider("flutterwave", "Flutterwave", "payments", ("flutterwave", "rave"), "provider-specific"),
    Provider("monnify", "Monnify", "payments", ("monnify",), "provider-specific"),
    Provider("korapay", "KoraPay", "payments", ("korapay", "kora pay"), "provider-specific"),
    Provider("seerbit", "SeerBit", "payments", ("seerbit",), "provider-context"),
    Provider("interswitch", "Interswitch", "payments", ("interswitch", "webpay"), "provider-specific"),
    Provider("remita", "Remita", "payments", ("remita",), "provider-context"),
    Provider("opay", "OPay", "payments", ("opay", "o-pay"), "provider-context"),
    Provider("palmpay", "PalmPay", "payments", ("palmpay", "palm pay", "palm-pay"), "provider-context"),
    Provider("squad", "Squad", "payments", ("squad",), "provider-context"),
    Provider("payaza", "Payaza", "payments", ("payaza",), "provider-context"),
    Provider("klasha", "Klasha", "payments", ("klasha",), "provider-context"),
    Provider("sudo", "Sudo", "fintech", ("sudo",), "provider-context"),
    Provider("brass", "Brass", "fintech", ("brass",), "provider-context"),
    Provider("anchor", "Anchor", "fintech", ("anchor",), "provider-context"),
    Provider("mono", "Mono", "open-banking", ("mono",), "provider-context"),
    Provider("okra", "Okra", "open-banking", ("okra",), "provider-context"),
    Provider("stitch", "Stitch", "payments", ("stitch",), "provider-context"),
    Provider("dapi", "Dapi", "open-banking", ("dapi",), "provider-context"),
    Provider("paga", "Paga", "payments", ("paga",), "provider-context"),
    Provider("carbon", "Carbon", "fintech", ("carbon",), "provider-context"),
    Provider("fairmoney", "FairMoney", "fintech", ("fairmoney", "fair money"), "provider-context"),
    Provider("cowrywise", "Cowrywise", "fintech", ("cowrywise",), "provider-context"),
    Provider("piggyvest", "PiggyVest", "fintech", ("piggyvest", "piggy vest"), "provider-context"),
    Provider("vfd", "VFD", "banking", ("vfd",), "provider-context"),
    Provider("providus", "Providus", "banking", ("providus",), "provider-context"),
    Provider("rubies", "Rubies", "banking", ("rubies",), "provider-context"),
    Provider("bamboo", "Bamboo", "fintech", ("bamboo",), "provider-context"),
    Provider("rise", "Rise", "fintech", ("rise", "risevest"), "provider-context"),
    Provider("gomoney", "GoMoney", "fintech", ("gomoney", "go money"), "provider-context"),
)

PROVIDER_BY_ID = {provider.id: provider for provider in PROVIDERS}
