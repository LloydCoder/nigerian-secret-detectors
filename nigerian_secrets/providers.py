from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Provider:
    id: str
    name: str
    category: str
    aliases: tuple[str, ...] = ()


# Provider names are metadata/context signals only. They are not claims that a
# provider exposes a particular credential format. Provider-specific formats
# belong in dedicated rules when independently established.
PROVIDERS: tuple[Provider, ...] = (
    Provider("paystack", "Paystack", "payments", ("paystack",)),
    Provider("flutterwave", "Flutterwave", "payments", ("flutterwave", "rave")),
    Provider("monnify", "Monnify", "payments", ("monnify",)),
    Provider("korapay", "KoraPay", "payments", ("korapay", "kora pay")),
    Provider("seerbit", "SeerBit", "payments", ("seerbit",)),
    Provider("interswitch", "Interswitch", "payments", ("interswitch", "webpay")),
    Provider("remita", "Remita", "payments", ("remita",)),
    Provider("opay", "OPay", "payments", ("opay", "o-pay")),
    Provider("palmpay", "PalmPay", "payments", ("palmpay", "palm pay", "palm-pay")),
    Provider("squad", "Squad", "payments", ("squad",)),
    Provider("payaza", "Payaza", "payments", ("payaza",)),
    Provider("klasha", "Klasha", "payments", ("klasha",)),
    Provider("sudo", "Sudo", "fintech", ("sudo",)),
    Provider("brass", "Brass", "fintech", ("brass",)),
    Provider("anchor", "Anchor", "fintech", ("anchor",)),
    Provider("mono", "Mono", "open-banking", ("mono",)),
    Provider("okra", "Okra", "open-banking", ("okra",)),
    Provider("stitch", "Stitch", "payments", ("stitch",)),
    Provider("dapi", "Dapi", "open-banking", ("dapi",)),
    Provider("paga", "Paga", "payments", ("paga",)),
    Provider("carbon", "Carbon", "fintech", ("carbon",)),
    Provider("fairmoney", "FairMoney", "fintech", ("fairmoney", "fair money")),
    Provider("cowrywise", "Cowrywise", "fintech", ("cowrywise",)),
    Provider("piggyvest", "PiggyVest", "fintech", ("piggyvest", "piggy vest")),
    Provider("vfd", "VFD", "banking", ("vfd",)),
    Provider("providus", "Providus", "banking", ("providus",)),
    Provider("rubies", "Rubies", "banking", ("rubies",)),
    Provider("bamboo", "Bamboo", "fintech", ("bamboo",)),
    Provider("rise", "Rise", "fintech", ("rise", "risevest")),
    Provider("gomoney", "GoMoney", "fintech", ("gomoney", "go money")),
)

PROVIDER_BY_ID = {provider.id: provider for provider in PROVIDERS}
