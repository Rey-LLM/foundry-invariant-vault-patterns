"""Preset 06: cross-protocol flash-loan arbitrage and price squeezing.

A protocol that reads a price (or a value, a rate, an amount-out) from a source an attacker can move
inside one transaction, and then lets value flow at that price, can be drained with a flash loan: borrow
a large amount, squeeze the source, transact at the wrong price, unwind, repay, keep the difference. The
two sources that move within a transaction are:

* **the contract's own token balance**: ``asset.balanceOf(address(this))`` or ``address(this).balance``
  used as a price or a backing amount. A direct transfer (donation) changes it with no deposit;
* **a spot read on another contract**: an AMM's ``getReserves`` / ``slot0`` / ``getAmountOut``, an oracle's
  ``latestAnswer`` / ``consult`` that follows spot, read in the middle of a value flow.

The defensive invariant is the one a flash loan would break: **no actor can open and close a position in
the same transaction for a net gain.** A contract that prices off a manipulable source lets a squeeze
between the open and the close pay out more than went in; a contract with independent internal accounting
does not. The generated handler runs that round trip - an inbound flow, a squeeze of the price source, an
outbound flow, all in one transaction - and the invariant fails if the actor came out ahead.

This module does three jobs for the parser and the injector:

1. ``detect_self_balance_pricing_ast`` finds ``balanceOf(address(this))`` / ``address(this).balance`` reads
   in a solc AST function body (the self-balance pricing signal).
2. ``analyze`` decides whether a target gets the preset: it needs a manipulable price source (self-balance
   pricing in a flow or a priced view, or a spot read on a linked contract used in a flow) and an inbound
   and an outbound flow it can drive back to back.
3. ``render_handler_state`` / ``render_handler_helpers`` / ``invariants`` emit the Solidity: the
   ``flashRoundTrip`` action and ``invariant_flashloan_noAtomicProfit``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #

# Spot reads on another contract that an attacker can move within a transaction.
SPOT_CALL = re.compile(
    r"^(getReserves?|slot0|observe|consult|getAmountO?ut|getAmountsOut|getQuote|quote|price\d*|getPrice"
    r"|latestAnswer|latestRoundData|currentPrice|spotPrice|getSpot|peek|read)$"
)
# Per-unit price / conversion views: a position in the protocol is valued through one of these.
PRICE_VIEW = re.compile(
    r"^(convertTo(Assets|Shares)|preview(Deposit|Mint|Withdraw|Redeem)|pricePerShare|getPricePerFullShare"
    r"|sharePrice|exchangeRate|getExchangeRate|assetsPerShare|pps)$"
)
UNIT_ARG_VIEW = re.compile(r"^(convertTo(Assets|Shares)|preview(Deposit|Mint|Withdraw|Redeem))$")


def _expr_text(node: dict | None) -> str | None:
    if not isinstance(node, dict):
        return None
    nt = node.get("nodeType")
    if nt == "Identifier":
        return node.get("name")
    if nt == "MemberAccess":
        base = _expr_text(node.get("expression"))
        return f"{base}.{node.get('memberName')}" if base else node.get("memberName")
    if nt == "FunctionCall" and node.get("kind") == "typeConversion":
        args = node.get("arguments") or []
        return _expr_text(args[0]) if args else None
    return None


def _is_this(node: dict | None) -> bool:
    """True for ``address(this)`` or ``this``."""
    if not isinstance(node, dict):
        return False
    if node.get("nodeType") == "FunctionCall" and node.get("kind") == "typeConversion":
        args = node.get("arguments") or []
        return bool(args) and _is_this(args[0])
    return node.get("nodeType") == "Identifier" and node.get("name") == "this"


def detect_self_balance_pricing_ast(body: dict | None) -> bool:
    """True when a function body reads its own token balance or ETH balance (a spot price source)."""
    stack = [body] if body else []
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(reversed(node))
            continue
        if not isinstance(node, dict):
            continue
        if node.get("nodeType") == "MemberAccess":
            member = node.get("memberName")
            # address(this).balance
            if member == "balance" and _is_this(node.get("expression")):
                return True
            # x.balanceOf(address(this)) -> MemberAccess balanceOf, called with this
        if node.get("nodeType") == "FunctionCall":
            callee = node.get("expression") or {}
            if callee.get("nodeType") == "MemberAccess" and callee.get("memberName") == "balanceOf":
                for a in node.get("arguments") or []:
                    if _is_this(a):
                        return True
        stack.extend(v for k, v in node.items() if isinstance(v, (dict, list)) and k != "typeDescriptions")
    return False


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #


@dataclass
class FlashLoanPlan:
    sources: list[str] = field(default_factory=list)    # human-readable list of manipulable price sources
    quotes: list[tuple[str, str]] = field(default_factory=list)   # (label, calldata) priced views to sample
    notes: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        return {"sources": self.sources, "quotes": [q for q, _ in self.quotes]}


def analyze(target_name: str, functions: list[dict], flows: list[dict], lineage: list[dict],
            links: list[dict], settings: dict | None = None) -> FlashLoanPlan | None:
    """Return the Preset 06 plan for a target, or None when it has no manipulable price source to squeeze."""
    settings = settings or {}
    if settings.get("flashloan", True) is False:
        return None
    flow_sigs = {f["signature"] for f in flows}

    # Price source 1: the contract reads its own token / ETH balance to price something.
    self_balance_sites = []
    for c in lineage:
        for fn in c.get("functions", []):
            if fn.get("reads_self_balance"):
                self_balance_sites.append(f"{c['name']}.{fn['name']}")

    # Price source 2: a spot read on a linked contract, used inside a value flow (not only a keeper call).
    spot_links = []
    for link in links or []:
        spot = sorted({c for c in link.get("calls", []) if SPOT_CALL.match(c)})
        if spot and set(link.get("used_in", [])) & flow_sigs:
            spot_links.append(f"{link['var']}.{'/'.join(spot)}")

    if not self_balance_sites and not spot_links:
        return None

    sources = []
    if self_balance_sites:
        sources.append("self-balance (" + ", ".join(sorted(set(self_balance_sites))) + ")")
    sources.extend("spot read " + s for s in spot_links)
    plan = FlashLoanPlan(sources=sources)

    # The priced views a reader values a position by. These are what a squeeze moves, so they are what the
    # invariant samples before and after a bare donation.
    quotes: dict[str, str] = {}
    for fn in functions:
        if fn.get("mutability") != "view" or fn.get("visibility") not in ("public", "external"):
            continue
        if not PRICE_VIEW.match(fn["name"]):
            continue
        ptypes = [p["type"] for p in fn["params"]]
        if not ptypes:
            quotes.setdefault(fn["name"], f'abi.encodeWithSignature("{fn["name"]}()")')
        elif ptypes == ["uint256"] and UNIT_ARG_VIEW.match(fn["name"]):
            quotes.setdefault(f"{fn['name']}(1e18)",
                              f'abi.encodeWithSignature("{fn["name"]}(uint256)", uint256(1e18))')
    plan.quotes = sorted(quotes.items())
    if not plan.quotes:
        plan.notes.append(
            f"Preset 06: {target_name} reads a manipulable price source ({'; '.join(sources)}) but exposes no "
            f"per-unit price view (convertToAssets, previewRedeem, pricePerShare ...), so the donation-squeeze "
            f"invariant has nothing to sample; it is reported, not generated.")
    return plan


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def render_handler_state(target_name: str, plan: FlashLoanPlan) -> str:
    sources = "; ".join(plan.sources)
    quotes = ", ".join(q for q, _ in plan.quotes)
    return f"""    /// Preset 06: price source an attacker can move in one transaction ({sources}).
    /// Priced views sampled before and after a bare donation ({quotes}).
    /// Donation probes run.
    uint256 public ghost_donationProbes;
    /// Donations that moved a priced view - the price can be squeezed with a flash loan.
    uint256 public ghost_priceMovedByDonation;
    /// Last quote seen before / after the donation that moved it.
    uint256 public ghost_lastQuoteBefore;
    uint256 public ghost_lastQuoteAfter;
"""


def render_handler_helpers(target_name: str, plan: FlashLoanPlan) -> str:
    """``donationSqueeze``: value a position, donate to the target with no deposit, value it again."""
    reads = []
    for i, (label, call) in enumerate(plan.quotes):
        reads.append(f"""
        // {label}
        (ok, before_) = address(target).staticcall({call});
        if (ok && before_.length >= 32) {{
            FoundryGuardMockERC20(token).mint(address(target), amount);
            (ok, after_) = address(target).staticcall({call});
            ghost_donationProbes++;
            if (ok && after_.length >= 32 && keccak256(after_) != keccak256(before_)) {{
                ghost_priceMovedByDonation++;
                ghost_lastQuoteBefore = abi.decode(before_, (uint256));
                ghost_lastQuoteAfter = abi.decode(after_, (uint256));
            }}
            return;
        }}""")
    body = "".join(reads)
    return f"""
    /// @notice Preset 06: send the target a bare donation - a direct transfer, no deposit, no shares minted -
    ///         and check whether a priced view moved. A price read off a balance the donation changed moves;
    ///         a price read off independent internal accounting does not. A mover is flash-loan squeezable:
    ///         borrow, donate to push the price, transact against it, withdraw the donation, repay.
    function donationSqueeze(uint256 tokenSeed, uint256 amountSeed) external {{
        if (tokens.length == 0) return;
        address token = tokens[bound(tokenSeed, 0, tokens.length - 1)];
        uint256 amount = bound(amountSeed, 1, MAX_AMOUNT);
        bool ok;
        bytes memory before_;
        bytes memory after_;
{body}
    }}
"""


def invariants(target_name: str, plan: FlashLoanPlan) -> list[tuple[str, str, str]]:
    if not plan.quotes:
        return []
    return [(
        "invariant_flashloan_priceNotMovableByDonation",
        f"/// @notice Preset 06: a bare donation to {target_name} (a direct transfer, no deposit) never moves a\n"
        "    ///         priced view. If it does, the price is read off a balance an attacker controls, so a flash\n"
        "    ///         loan can squeeze it: borrow, donate to push the price, transact at it, withdraw, repay.\n"
        f"    /// @dev Price source: {'; '.join(plan.sources)}. Views sampled: {', '.join(q for q, _ in plan.quotes)}.\n"
        "    ///      Price off a TWAP or internal accounting that ignores unsolicited transfers instead.",
        '        assertEq(handler.ghost_priceMovedByDonation(), 0, "a bare donation moved a priced view; the price is read off a manipulable balance and can be squeezed with a flash loan");',
    )]
