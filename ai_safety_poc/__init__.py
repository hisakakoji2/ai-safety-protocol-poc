"""Proof of concept of an AI safety protocol built from three parts.

1. Record: a tamper-evident, append-only ledger of AI action fingerprints
   (modelled on Certificate Transparency, RFC 9162), watched by independent
   witnesses.
2. Lottery audit: actions are picked for deep audit by public randomness,
   with probability proportional to their impact.
3. Fine formula: a detected violation is fined damage / (audit probability x
   detection rate), so the expected fine equals the damage and cheating does
   not pay.

No blockchain and no token are used. Amounts are plain numbers (yen).
"""

__version__ = "0.1.0"
