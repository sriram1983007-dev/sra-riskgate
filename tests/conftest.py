from datetime import date, timedelta

import pytest

import sra_riskgate.client as client
from sra_riskgate.sanctions import bundled_as_of


@pytest.fixture(autouse=True)
def fixed_today(monkeypatch):
    """Pin "today" to just after the bundled sanctions snapshot, so results do not change with the
    calendar (the SANCTIONS_LIST_STALE flag would otherwise appear in every test 90 days after
    release). Tests that need another date call ``fixed_today(some_date)``."""
    def set_today(d: date) -> None:
        monkeypatch.setattr(client, "_today", lambda: d)

    set_today(date.fromisoformat(bundled_as_of()) + timedelta(days=1))
    return set_today
