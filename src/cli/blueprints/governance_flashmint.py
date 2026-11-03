"""Preset 07: governance flash-mint vote hijacking.

A governance system is safe only if the weight a vote carries is fixed to a moment the attacker cannot
reach: a snapshot taken when the proposal was created, or a historical checkpoint one block in the past.
When the weight comes from a *live* reading instead - the account's current balance, ``getVotes`` of the
current block, the current ``totalSupply`` - an attacker flash-mints or flash-borrows the governance
token, votes with it, and returns it, all in one transaction. The proposal is decided by tokens the
attacker never really held.

The tell is in how an account's voting power is read. If the power an account has *right now* can be
raised by tokens it acquired *in this same block*, the vote weight is live and a flash loan swings it. A
checkpointed design (OpenZeppelin ``ERC20Votes`` + ``getPastVotes``, ``ERC20Snapshot``, a balance recorded
at proposal time) returns the same power no matter what the account acquires in the current block, so the
flash-minted tokens carry no weight.

The generated handler acquires a large amount of the governance token for an actor in one transaction and
reads the actor's voting power before and after. The invariant fails if the power rose: that rise is
exactly the weight a flash loan would vote with and then hand back.

This module does three jobs for the parser and the injector:

1. ``detect_vote_weighting_ast`` records, per function, whether its body reads a *live* weight
   (``balanceOf``, ``getVotes``/``getCurrentVotes``, ``totalSupply``) or a *past* checkpoint
   (``getPastVotes``, ``getPriorVotes``, ``balanceOfAt`` ...).
2. ``analyze`` decides whether a target gets the preset: it needs a vote entry point and a per-account
   voting-power getter, and - for the runnable invariant - a way the handler can grant the governance
   token in-test (a public ``mint`` / ``issue`` the contract exposes).
3. ``render_handler_state`` / ``render_handler_helpers`` / ``invariants`` emit the Solidity: the
   ``flashVote`` action and ``invariant_governance_powerNotFlashInflatable``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #

VOTE_FN = re.compile(r"^(castVote\w*|vote\w*|_?countVotes?|submitVote|voteFor|voteAgainst|voteYes|voteNo)$")
# Per-account voting-power getters, read at the current block.
POWER_GETTER = re.compile(r"^(getVotes|getCurrentVotes|votingPower|getVotingPower|votes|voteWeight|weightOf|powerOf)$")
# Historical / snapshot getters: their presence is the safe signal.
PAST_GETTER = re.compile(
    r"^(getPastVotes|getPriorVotes|getPastTotalSupply|balanceOfAt|getVotesAt|getPastVotingPower"
    r"|votesAt|getPriorBalance|pastBalanceOf)$")
# Live weight sources read inside a vote function.
LIVE_READ = re.compile(r"^(balanceOf|getVotes|getCurrentVotes|totalSupply|balanceOfNow)$")
# Ways the handler can create governance-token balance from nothing, in one transaction.
GRANT_FN = re.compile(r"^(mint|mintTo|issue|issueTo|airdrop|grant|grantTokens)$")


def _callee_name(node: dict | None) -> str | None:
    if not isinstance(node, dict) or node.get("nodeType") != "FunctionCall":
        return None
    callee = node.get("expression") or {}
    if callee.get("nodeType") == "MemberAccess":
        return callee.get("memberName")
    if callee.get("nodeType") == "Identifier":
        return callee.get("name")
    return None


def _arg_count(node: dict) -> int:
    return len(node.get("arguments") or [])


def detect_vote_weighting_ast(body: dict | None) -> dict:
    """Per-function record of how it reads voting weight: live balance vs a past checkpoint."""
    reads_live = reads_past = False
    stack = [body] if body else []
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(reversed(node))
            continue
        if not isinstance(node, dict):
            continue
        if node.get("nodeType") == "FunctionCall":
            name = _callee_name(node) or ""
            if PAST_GETTER.match(name):
                reads_past = True
            elif LIVE_READ.match(name):
                # getVotes(account) is live; getPastVotes(account, block) is past (handled above).
                if name not in ("getVotes", "getCurrentVotes") or _arg_count(node) <= 1:
                    reads_live = True
        stack.extend(v for k, v in node.items() if isinstance(v, (dict, list)) and k != "typeDescriptions")
    return {"reads_live": reads_live, "reads_past": reads_past}


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #


@dataclass
class GovernancePlan:
    vote_fns: list[str]                                 # vote entry points
    power_getter: str | None = None                     # per-account current voting-power getter
    power_is_balance: bool = False                      # power getter is plain balanceOf (weight == live balance)
    grant: dict | None = None                           # {"signature", "name", "account_first": bool} mint-like fn
    uses_live: bool = False
    uses_past: bool = False
    notes: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        return {"vote_fns": self.vote_fns, "power_getter": self.power_getter,
                "power_is_balance": self.power_is_balance, "grant": self.grant["signature"] if self.grant else None,
                "uses_live": self.uses_live, "uses_past": self.uses_past,
                "weight_source": "live" if self.uses_live and not self.uses_past else
                                 "checkpoint" if self.uses_past and not self.uses_live else
                                 "mixed" if self.uses_live and self.uses_past else "unknown"}


def _addr_uint(params: list[dict]) -> bool | None:
    """(address, uint) -> True, (uint, address) -> False, anything else -> None."""
    types = [p["type"] for p in params]
    if types == ["address", "uint256"]:
        return True
    if types == ["uint256", "address"]:
        return False
    return None


def analyze(target_name: str, functions: list[dict], flows: list[dict], lineage: list[dict],
            settings: dict | None = None) -> GovernancePlan | None:
    """Return the Preset 07 plan for a target, or None when it is not a governance contract."""
    settings = settings or {}
    if settings.get("governance", True) is False:
        return None

    vote_fns = sorted({f["signature"] for f in functions
                       if VOTE_FN.match(f["name"]) and f.get("mutability") in ("nonpayable", "payable")})
    # A per-account current-power getter: a dedicated one first, else plain balanceOf.
    power_getter = None
    power_is_balance = False
    for fn in functions:
        if (POWER_GETTER.match(fn["name"]) and fn.get("mutability") == "view"
                and [p["type"] for p in fn["params"]] == ["address"]
                and [r["type"] for r in fn.get("returns", [])][:1] in (["uint256"], ["uint224"], ["uint96"])):
            power_getter = fn["name"]
            break
    if power_getter is None:
        for fn in functions:
            if (fn["name"] == "balanceOf" and fn.get("mutability") == "view"
                    and [p["type"] for p in fn["params"]] == ["address"]):
                power_getter, power_is_balance = "balanceOf", True
                break

    if not vote_fns or power_getter is None:
        return None  # not a governance contract we can reason about

    plan = GovernancePlan(vote_fns=vote_fns, power_getter=power_getter, power_is_balance=power_is_balance)

    # Static read of the vote functions: live weight, past checkpoint, or both.
    for c in lineage:
        for fn in c.get("functions", []):
            if not VOTE_FN.match(fn["name"]):
                continue
            w = fn.get("vote_weighting") or {}
            plan.uses_live = plan.uses_live or bool(w.get("reads_live"))
            plan.uses_past = plan.uses_past or bool(w.get("reads_past"))

    # A mint-like function the handler can call to flash-acquire the governance token in one transaction.
    def is_admin(fn: dict) -> bool:
        return any(re.match(r"^(only[A-Z_]\w*|onlyOwner|auth|restricted|ownerOnly|adminOnly)$", m)
                   for m in fn.get("modifiers", []))
    for fn in functions:
        if (GRANT_FN.match(fn["name"]) and fn.get("visibility") in ("public", "external")
                and fn.get("mutability") in ("nonpayable", "payable") and not is_admin(fn)):
            order = _addr_uint(fn["params"])
            if order is not None:
                plan.grant = {"signature": fn["signature"], "name": fn["name"], "account_first": order}
                break

    if plan.grant is None:
        plan.notes.append(
            f"Preset 07: {target_name} weights votes by an account's current power ({power_getter}) but exposes no "
            f"public mint/issue the test can flash-acquire with, so the flash-vote invariant is not generated; give "
            f"[contracts.{target_name}] a grant function or a mock governance token to drive it.")
    if plan.uses_past and not plan.uses_live:
        plan.notes.append(
            f"Preset 07: {target_name} reads a past checkpoint (getPastVotes-style) when it counts votes, which is "
            f"the flash-mint-resistant design; the invariant will confirm current power is not inflatable in-block.")
    return plan


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def render_handler_state(target_name: str, plan: GovernancePlan) -> str:
    return f"""    /// Preset 07: flash-vote probes run (acquire the governance token in one block, read power).
    uint256 public ghost_flashVoteProbes;
    /// Times an account's voting power rose from tokens acquired in the same block (flash-inflatable).
    uint256 public ghost_flashPowerGain;
    /// Largest same-block power increase observed.
    uint256 public ghost_flashPowerDelta;
"""


def render_handler_helpers(target_name: str, plan: GovernancePlan) -> str:
    g = plan.grant
    grant_args = "actor, flash" if g["account_first"] else "flash, actor"
    return f"""
    /// @dev Preset 07: reads an account's current voting power through {plan.power_getter}().
    function _votingPower(address account) internal view returns (bool ok, uint256 power) {{
        bytes memory ret;
        (ok, ret) = address(target).staticcall(
            abi.encodeWithSignature("{plan.power_getter}(address)", account)
        );
        if (ok && ret.length >= 32) power = abi.decode(ret, (uint256));
        else ok = false;
    }}

    /// @notice Preset 07: acquire a large amount of the governance token for one actor in this single
    ///         transaction - as a flash mint or flash loan would - and measure the actor's voting power
    ///         before and after. A rise is weight a flash loan would vote with and then hand straight back.
    function flashVote(uint256 actorSeed, uint256 amountSeed) external {{
        address actor = _actor(actorSeed);
        (bool ok0, uint256 power0) = _votingPower(actor);
        if (!ok0) return;
        uint256 flash = bound(amountSeed, 1, MAX_AMOUNT);
        (bool granted, ) = address(target).call(abi.encodeWithSignature("{g['signature']}", {grant_args}));
        if (!granted) return;
        ghost_flashVoteProbes++;
        (bool ok1, uint256 power1) = _votingPower(actor);
        if (ok1 && power1 > power0) {{
            ghost_flashPowerGain++;
            if (power1 - power0 > ghost_flashPowerDelta) ghost_flashPowerDelta = power1 - power0;
        }}
    }}
"""


def invariants(target_name: str, plan: GovernancePlan) -> list[tuple[str, str, str]]:
    if not plan.grant:
        return []
    weight = "the account's live balance" if plan.power_is_balance else f"{plan.power_getter}()"
    return [(
        "invariant_governance_powerNotFlashInflatable",
        f"/// @notice Preset 07: an account's voting power ({weight}) never rises from governance tokens it\n"
        "    ///         acquired in the current block. If it does, a flash loan votes with that power and returns\n"
        "    ///         the tokens in the same transaction, hijacking the proposal.\n"
        f"    /// @dev Weight votes by a snapshot taken at proposal creation or a past checkpoint (getPastVotes),\n"
        f"    ///      not by current power. Static read of the vote path: "
        f"{'live weight' if plan.uses_live and not plan.uses_past else 'past checkpoint' if plan.uses_past and not plan.uses_live else 'review it'}.",
        '        assertEq(handler.ghost_flashPowerGain(), 0, "voting power rose from tokens acquired in the same block; a flash loan can vote with them and return them (weight votes by a past checkpoint instead)");',
    )]
