"""Offline screening against a snapshot of the OFAC SDN list's EVM addresses.

The bundled list holds the Ethereum-format addresses that OFAC (US Treasury) publishes on its
Specially Designated Nationals list, as extracted by the open-source
`ofac-sanctioned-digital-currency-addresses` project. The same address format is used on Base and
other EVM chains.

This is a snapshot: addresses added to the SDN list after ``BUNDLED_AS_OF`` are not included. It
matches exact addresses only; it does not trace funds, resolve ownership or cover other sanctions
programmes. Use it as a fast first layer and keep your screening provider as the source of truth.
To use a fresher list, load it with ``SanctionsList.from_file()`` or ``SanctionsList.from_addresses()``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Iterable, Optional

_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_BUNDLED_FILE = "data/ofac_sdn_evm.txt"
FLAG = "OFAC_SDN_MATCH"
NOT_CHECKED_FLAG = "SANCTIONS_NOT_CHECKED"


def _normalise(address: object) -> Optional[str]:
    if not isinstance(address, str):
        return None
    a = address.strip()
    return a.lower() if _ADDRESS.match(a) else None


@dataclass(frozen=True)
class SanctionsList:
    """A set of sanctioned EVM addresses, with where it came from and how current it is."""

    addresses: frozenset = field(repr=False)
    source: str = "custom"
    as_of: str = "unknown"

    def __post_init__(self):
        if not self.addresses:
            raise ValueError("A sanctions list must contain at least one valid 0x address.")

    @classmethod
    def from_addresses(cls, addresses: Iterable[str], source: str = "custom", as_of: str = "unknown"
                       ) -> "SanctionsList":
        """Build a list from addresses. Anything that is not a 0x-prefixed 40-hex address raises ValueError."""
        parsed = set()
        for a in addresses:
            n = _normalise(a)
            if n is None:
                raise ValueError(f"Not an EVM address: {a!r}")
            parsed.add(n)
        return cls(frozenset(parsed), source=source, as_of=as_of)

    @classmethod
    def _from_text(cls, text: str, source: str) -> "SanctionsList":
        as_of = "unknown"
        lines = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            if line.startswith("#"):
                m = re.search(r"as_of:\s*(\S+)", line)
                if m:
                    as_of = m.group(1)
                continue
            lines.append(line)
        return cls.from_addresses(lines, source=source, as_of=as_of)

    @classmethod
    def from_file(cls, path: str | Path, as_of: Optional[str] = None) -> "SanctionsList":
        """Load one address per line; lines starting with # are comments. Fails on any invalid line."""
        p = Path(path)
        lst = cls._from_text(p.read_text(encoding="utf-8"), source=str(p))
        return lst if as_of is None else cls(lst.addresses, source=lst.source, as_of=as_of)

    @classmethod
    def bundled(cls) -> "SanctionsList":
        """The snapshot shipped with this package (cached after the first call)."""
        global _BUNDLED
        if _BUNDLED is None:
            text = resources.files("sra_riskgate").joinpath(_BUNDLED_FILE).read_text(encoding="utf-8")
            _BUNDLED = cls._from_text(text, source="OFAC SDN list (bundled snapshot)")
        return _BUNDLED

    def __len__(self) -> int:
        return len(self.addresses)

    def __contains__(self, address: object) -> bool:
        n = _normalise(address)
        return n is not None and n in self.addresses

    def screen(self, sender: object, recipient: object) -> list[tuple[str, str]]:
        """Return (party, address) for each of sender and recipient found on the list."""
        hits = []
        for party, addr in (("recipient", recipient), ("sender", sender)):
            if addr in self:
                hits.append((party, _normalise(addr)))
        return hits

    def describe(self) -> str:
        return f"{self.source}, as of {self.as_of}, {len(self)} addresses"


_BUNDLED: Optional[SanctionsList] = None


def is_sanctioned(address: str, sanctions_list: Optional[SanctionsList] = None) -> bool:
    """True if ``address`` is on ``sanctions_list`` (default: the bundled OFAC SDN snapshot)."""
    return address in (sanctions_list or SanctionsList.bundled())


def bundled_as_of() -> str:
    """Date of the bundled snapshot (the last change to the upstream list it was taken from)."""
    return SanctionsList.bundled().as_of
