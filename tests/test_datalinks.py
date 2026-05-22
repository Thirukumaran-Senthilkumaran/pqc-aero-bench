from pqc_aero_bench.datalinks import DATALINKS, get, all_datalinks


def test_catalogue_is_nonempty():
    assert len(DATALINKS) >= 6
    names = {d.name for d in all_datalinks()}
    expected = {
        "ACARS-VHF",
        "VDL-Mode-2",
        "ADS-B-1090ES",
        "LDACS",
        "SATCOM-Classic-Aero",
        "AeroMACS",
    }
    assert expected.issubset(names)


def test_lookup_tolerant():
    assert get("ACARS-VHF").name == "ACARS-VHF"
    assert get("acars-vhf").name == "ACARS-VHF"


def test_airtime_monotonic():
    """Bigger payload -> larger airtime, on every link."""
    for d in all_datalinks():
        t1 = d.airtime_ms(100)
        t2 = d.airtime_ms(1000)
        assert t2 >= t1


def test_fragmentation_math():
    d = get("ACARS-VHF")
    assert d.fragments_required(0) == 0
    assert d.fragments_required(d.max_payload_bytes) == 1
    assert d.fragments_required(d.max_payload_bytes + 1) == 2
    assert d.fragments_required(d.max_payload_bytes * 5) == 5


def test_adsb_is_severely_constrained():
    """ADS-B has a 7-byte ADS-B Message Field; this is the whole point of
    the project. Guard it with a test so a refactor never quietly relaxes
    the constraint."""
    assert get("ADS-B-1090ES").max_payload_bytes == 7
