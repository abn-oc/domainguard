import re

from domainguard.dga.evasion_generators import EVASION_FAMILIES, generate_evasion_family
from domainguard.dga.generators import FAMILIES, generate_all, generate_family

ALPHABETS = {
    "rand_alnum": re.compile(r"^[a-z0-9]{8,20}$"),
    "hex": re.compile(r"^[0-9a-f]{16,32}$"),
    "cv_pronounceable": re.compile(r"^[a-z]{8,16}$"),
    "sparse_digits": re.compile(r"^[a-z0-9]{10,18}$"),
    "dict_join": re.compile(r"^[a-z]{8,24}$"),
}


def test_family_shape_and_determinism():
    for family in FAMILIES:
        first, collisions = generate_family(family, 100, seed=42)
        second, _ = generate_family(family, 100, seed=42)
        assert first == second
        assert len(first) == len(set(first)) == 100
        assert isinstance(collisions, int)
        pattern = ALPHABETS[family]
        assert all(pattern.match(name) for name in first), family


def test_generate_all_split_evenly():
    rows, _ = generate_all(1000, seed=42, excluded={"example"})
    assert len(rows) == 1000
    counts = {family: 0 for family in FAMILIES}
    for _name, family in rows:
        counts[family] += 1
    assert set(counts.values()) == {200}


def test_evasion_generators_are_strings_only():
    for family in EVASION_FAMILIES:
        names = generate_evasion_family(family, 25, seed=42)
        assert len(names) == 25
        assert all(isinstance(name, str) and name.islower() for name in names)
