"""pqc-aero-bench: Post-Quantum Cryptography benchmark for aviation datalinks.

A reproducible measurement framework that scores NIST-standardized PQC primitives
(ML-KEM/FIPS 203, ML-DSA/FIPS 204, SLH-DSA/FIPS 205) and the upcoming FN-DSA
(Falcon) against the hard physical-layer constraints of civil aviation datalinks
(ACARS, VDL Mode 2, ADS-B 1090ES, LDACS, SATCOM, AeroMACS).
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
