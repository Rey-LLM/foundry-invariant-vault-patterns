"""FoundryGuard invariant preset library.

Presets 01-03 (ERC-4626, single-unit vault / staking accounting, rewards) are rendered inline by
``injector.py``. Presets that need their own helper contracts live here as modules:

* ``hook_reentrancy`` - Preset 04, hook-based read-reentrancy for Uniswap v4 style hook architectures.
* ``transient_storage`` - Preset 05, EIP-1153 transient slots left set between calls in one transaction.
"""
