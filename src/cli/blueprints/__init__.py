"""FoundryGuard invariant preset library.

Presets 01-03 (ERC-4626, single-unit vault / staking accounting, rewards) are rendered inline by
``injector.py``. Presets that need their own helper contracts live here as modules:

* ``hook_reentrancy`` - Preset 04, hook-based read-reentrancy for Uniswap v4 style hook architectures.
* ``transient_storage`` - Preset 05, EIP-1153 transient slots left set between calls in one transaction.
* ``flashloan_price`` - Preset 06, a price squeezable by a flash loan (a bare donation moves a priced view).
* ``governance_flashmint`` - Preset 07, vote weight inflatable by tokens flash-minted in the same block.
* ``read_reentrancy_view`` - Preset 08, an economic view read while the contract pays the caller mid-flow.

Contracts none of these match can be handed to ``ai_generator.py`` (Layer 06 fallback, ``--ai``).
"""
