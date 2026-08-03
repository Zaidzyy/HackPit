"""HackPit-side out-of-band canary support (build #13 part 3).

This package is the HALF THAT STAYS HOME. It mints canary tokens and correlates a hit back
to the test that caused it. The listener those hits arrive at is ``oob/server.py`` at the
repository root — a separate, stdlib-only file that is copied to a VPS you own and never
imported from here.

Keeping the two apart is deliberate. The deployable is internet-facing and must stay a
single file with no install step; this side runs inside HackPit next to the engagement
record. Nothing in this package opens a socket or runs a command — locked by
test_oob_tokens.py.
"""
