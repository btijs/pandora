from __future__ import annotations

import logging
from collections import defaultdict

import angr
import claripy
from angr.exploration_techniques import ExplorationTechnique
from capstone import CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_V8, Cs
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG

logger = logging.getLogger(name="ManualMerger")

# --- Automatic merge-point detection -----------------------------------------
#
# A good merge point is a *pure, branchy leaf* function: it reads its arguments,
# branches a lot, and returns a value without side effects (think address-range
# checks such as `cmse_check_address_range`). Such functions are a classic
# source of path explosion, and because their only output is the return value,
# merging all paths on that value is sound.
#
# We detect them from the CFG (`project.kb.functions`, populated by CFGFast)
# using VEX IR so the analysis is architecture-independent:
#   - reject functions that call out (any block with an `Ijk_Call`/syscall jump),
#   - reject functions that write memory anywhere other than the stack (an
#     `Ist_Store`/`Ist_StoreG` whose address is not derived from SP),
#   - require at least one returning block, and merge at the *return
#     instruction* of each (not the block's entry): stopping there means the
#     return value is already final and callee-saved registers are restored,
#     so grouping states by the return value is sound (caller-saved registers
#     are dead scratch per the calling convention, and memory is unchanged),
#   - rank the survivors by how much they fan out in the CFG (the number of
#     extra successor edges, i.e. sum of `out_degree - 1` over blocks). This
#     counts multi-way branches such as a `tbb`/`tbh` table branch or an
#     `ldr pc, [...]` jump table by their resolved target count, which a raw
#     count of two-way conditional branches would miss.
#
# Hook awareness: Cortex-M intrinsics such as `TT`/`SG` are undecodable by VEX
# and are modelled by hooking their address with a SimProcedure (see
# arm_hooker.py). Raw VEX lifts the block up to such an instruction and marks it
# `Ijk_NoDecode`. These intrinsics are pure register operations and part of the
# leaf (e.g. `cmse_check_address_range` is built on `TT`), so a NoDecode block
# that ends at one of them is treated as benign rather than discarding the
# function; a NoDecode at anything else means we cannot vet the function.

# Require at least this much CFG fan-out (extra successor edges) to be worth merging.
MIN_BRANCHES = 2
# Cap the number of merge-point techniques we install (each adds step overhead).
MAX_CANDIDATES = 10
# Pure leaf checks are small; skip anything larger to avoid pathological cases.
MAX_BLOCKS = 64
# How many levels of calls a candidate may make. 0 means a pure leaf (no calls);
# with N > 0 a function may call other functions as long as each of them is
# itself a pure, side-effect-free function accepted at depth N - 1.
MAX_CALL_DEPTH = 1
# SimProcedure hooks that stand in for pure register-only instructions. A block
# ending in one of these (as Ijk_NoDecode) is still a pure leaf.
PURE_INSTRUCTION_HOOKS = frozenset({"SimTestTarget", "SimSG", "SimNop"})
# ARMv8-M intrinsics that VEX cannot decode but which are pure (register-only):
# the Test Target family and Secure Gateway. Identified by disassembly so the
# analysis does not depend on these addresses already being hooked.
PURE_INTRINSIC_MNEMONICS = frozenset({"tt", "ttt", "tta", "ttat", "sg"})
_thumb_v8_disassembler = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_V8)
_thumb_v8_detail = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_V8)
_thumb_v8_detail.detail = True


def _table_branch_fanout(project, func, block):
    """
    For a block ending in a `tbb`/`tbh` table branch, count the distinct switch
    targets by reading the table from memory. The number of entries is bounded by
    the dominating `cmp <index>, #k` (`k + 1` entries). Returns 0 if the block is
    not a table branch or the table cannot be read.

    This recovers the fan-out of a switch even when CFGFast failed to resolve it
    (e.g. because the case blocks contain hooked `TT` instructions), which would
    otherwise make a branchy function like `cmse_check_address_range` look small.
    """
    insn_addrs = block.instruction_addrs
    if not insn_addrs:
        return 0
    addr = insn_addrs[-1] & ~1
    try:
        insns = list(_thumb_v8_detail.disasm(bytes(project.loader.memory.load(addr, 4)), addr))
    except Exception:
        return 0
    if not insns or insns[0].mnemonic not in ("tbb", "tbh"):
        return 0
    tbr = insns[0]

    # Index register = the index of the memory operand (`tbb [pc, rN]`).
    index_reg = None
    for op in tbr.operands:
        if op.type == ARM_OP_MEM and op.mem.index != 0:
            index_reg = tbr.reg_name(op.mem.index)
    if index_reg is None:
        return 0

    # Table size from the dominating `cmp <index>, #k` anywhere in the function.
    max_bound = -1
    for block_addr in func.block_addrs_set:
        b = project.factory.block(block_addr)
        try:
            raw = bytes(project.loader.memory.load(block_addr & ~1, b.size))
        except Exception:
            continue
        for insn in _thumb_v8_detail.disasm(raw, block_addr & ~1):
            if insn.id and insn.mnemonic.startswith("cmp") and len(insn.operands) == 2:
                op0, op1 = insn.operands
                if op0.type == ARM_OP_REG and insn.reg_name(op0.reg) == index_reg and op1.type == ARM_OP_IMM:
                    max_bound = max(max_bound, op1.imm)
    if max_bound < 0:
        return 0
    size = max_bound + 1

    # Read the table (PC-relative: base is the address just after the branch) and
    # count distinct target addresses.
    base = addr + 4
    entry_size = 1 if tbr.mnemonic == "tbb" else 2
    try:
        raw = bytes(project.loader.memory.load(base, size * entry_size))
    except Exception:
        return 0
    targets = set()
    for i in range(size):
        if entry_size == 1:
            offset = raw[i]
        else:
            offset = raw[2 * i] | (raw[2 * i + 1] << 8)
        targets.add(base + 2 * offset)
    return len(targets)


def _expr_is_stack(expr, stack_regs, sp_tmps):
    """
    Return True if a VEX expression evaluates to a stack-frame address.

    `stack_regs` is the set of register offsets currently holding a
    stack-pointer-derived value (the stack pointer plus any frame pointer set up
    from it); `sp_tmps` is the set of stack-derived temporaries in this block.
    """
    tag = expr.tag
    if tag == "Iex_Get":
        return expr.offset in stack_regs
    if tag == "Iex_RdTmp":
        return expr.tmp in sp_tmps
    if tag == "Iex_Binop" and expr.op.startswith(("Iop_Add", "Iop_Sub", "Iop_And", "Iop_Or")):
        # `sp - 8` for a push, `fp + off` for a local slot, or `sp & ~3` for the
        # stack-alignment mask emitted in ARM prologues.
        return any(_expr_is_stack(arg, stack_regs, sp_tmps) for arg in expr.args)
    return False


def _is_pure_intrinsic(project, addr):
    """
    Return True if the instruction at `addr` is a pure, register-only Cortex-M
    intrinsic that VEX cannot decode (e.g. TT/SG).

    It is recognised either by an existing instruction hook (see arm_hooker.py)
    or, independently of hooking, by disassembling the bytes with Capstone.
    """
    for a in (addr, addr & ~1, addr | 1):
        if project.is_hooked(a):
            return type(project.hooked_by(a)).__name__ in PURE_INSTRUCTION_HOOKS

    if not project.arch.name.startswith("ARM"):
        return False
    base = addr & ~1
    try:
        raw = project.loader.memory.load(base, 4)
    except Exception:
        return False
    for insn in _thumb_v8_disassembler.disasm(bytes(raw), base):
        return insn.mnemonic in PURE_INTRINSIC_MNEMONICS
    return False


def _indirect_branch_is_switch(project, block):
    """
    Return True if a block's terminating indirect branch is an internal jump
    table (a `tbb`/`tbh` table branch or a pc-relative `ldr pc` switch) rather
    than an indirect tail call / function pointer (`bx reg`, `ldr pc, [reg]`).

    Decided by disassembly so it holds even when CFGFast's jump-table resolver
    did not register the table (e.g. because nearby instructions are hooked).
    """
    if not project.arch.name.startswith("ARM"):
        return False
    insn_addrs = block.instruction_addrs
    if not insn_addrs:
        return False
    addr = insn_addrs[-1] & ~1
    try:
        raw = project.loader.memory.load(addr, 4)
    except Exception:
        return False
    for insn in _thumb_v8_disassembler.disasm(bytes(raw), addr):
        if insn.mnemonic in ("tbb", "tbh"):
            return True
        # pc-relative dispatch table: `ldr pc, [pc, rN, ...]`
        return insn.mnemonic == "ldr" and insn.op_str.replace(" ", "").startswith("pc,[pc")
    return False


def _resolve_callee(project, irsb):
    """Return the called Function for a direct call block, or None if the call is
    indirect or its target is not a known function."""
    nxt = irsb.next
    if nxt.tag != "Iex_Const":
        return None  # indirect call (e.g. `blx reg`) -- unknown target
    target = nxt.con.value
    for addr in (target, target & ~1, target | 1):
        if addr in project.kb.functions:
            return project.kb.functions[addr]
    return None


def _is_pure_function(project, func, sp_offset, max_blocks, jump_table_targets, depth, memo):
    """Memoized predicate: is `func` side-effect-free within `depth` call levels?
    Returns (ok, reason, branch_count), where branch_count is the function's own
    fan-out plus that of everything it calls (used to rank a caller above its
    callees). Used for callees; ignores the merge-point addresses."""
    key = (func.addr, depth)
    if key in memo:
        return memo[key]
    # Pessimistic placeholder guards against call cycles (a recursive function
    # cannot be pure within a finite budget).
    memo[key] = (False, "recursive call", 0)
    ok, reason, _ret_addrs, branch_count = _scan_function(project, func, sp_offset, max_blocks, jump_table_targets, depth, memo)
    memo[key] = (ok, reason, branch_count)
    return memo[key]


def _scan_function(project, func, sp_offset, max_blocks, jump_table_targets, depth, memo):
    """
    Scan a function for side effects and collect its merge-point bookkeeping.

    Returns (ok, reason, ret_addrs, branch_count). `ok` is True if the function
    writes no non-stack memory, returns, transfers control only inside itself
    (plus resolved switches and pure intrinsics), and every function it calls is
    itself pure at `depth - 1` (so `depth == 0` forbids calls, i.e. a pure leaf).
    `branch_count` is the function's own CFG fan-out plus that of its callees.
    """
    if func.is_simprocedure or func.is_plt or func.is_syscall or func.is_alignment:
        return False, "not a normal function (simprocedure/plt/syscall/alignment)", [], 0
    if project.is_hooked(func.addr):
        return False, "function entry is hooked", [], 0

    block_addrs = sorted(func.block_addrs_set)
    if not block_addrs:
        return False, "no blocks", [], 0
    if len(block_addrs) > max_blocks:
        return False, f"too many blocks ({len(block_addrs)} > {max_blocks})", [], 0
    func_block_set = {a & ~1 for a in block_addrs}

    ret_addrs = []
    # block addr -> fan-out of a table branch (tbb/tbh) that ends it, read from
    # the table when CFGFast did not resolve it.
    switch_fanout: dict[int, int] = {}
    # Fan-out contributed by the functions this one calls (their own total).
    called_branch_count = 0

    # Register offsets that hold a stack-pointer-derived value. Starts with the
    # stack pointer and grows to include a frame pointer once the prologue sets
    # it up (e.g. `mov r7, sp`). Processing blocks in address order means the
    # prologue is seen before the blocks that use the frame pointer.
    stack_regs = {sp_offset}

    for block_addr in block_addrs:
        block = project.factory.block(block_addr)
        irsb = block.vex
        jumpkind = irsb.jumpkind

        # Syscalls always have side effects. A call is allowed only if we still
        # have call budget and the callee is itself a pure function.
        if jumpkind.startswith("Ijk_Sys"):
            return False, f"syscall at {block_addr:#x}", [], 0
        if jumpkind == "Ijk_Call":
            if depth <= 0:
                return False, f"calls out at {block_addr:#x} (call depth exhausted)", [], 0
            callee = _resolve_callee(project, irsb)
            if callee is None:
                return False, f"indirect / unresolved call at {block_addr:#x}", [], 0
            ok, reason, callee_branches = _is_pure_function(project, callee, sp_offset, max_blocks, jump_table_targets, depth - 1, memo)
            if not ok:
                return False, f"calls impure {callee.name} at {block_addr:#x} ({reason})", [], 0
            called_branch_count += callee_branches

        # Track which temporaries hold a stack-derived value within this block so
        # we can tell stack-frame spills from real memory writes. Also collect the
        # concrete branch targets (conditional exits + the fall-through) to detect
        # a direct branch out of the function below.
        sp_tmps: set[int] = set()
        branch_targets: list[int] = []
        for stmt in irsb.statements:
            tag = stmt.tag
            if tag == "Ist_WrTmp":
                if _expr_is_stack(stmt.data, stack_regs, sp_tmps):
                    sp_tmps.add(stmt.tmp)
            elif tag == "Ist_Put":
                # Track a frame pointer being set from / cleared of the stack.
                if _expr_is_stack(stmt.data, stack_regs, sp_tmps):
                    stack_regs.add(stmt.offset)
                elif stmt.offset != sp_offset:
                    stack_regs.discard(stmt.offset)
            elif tag in ("Ist_Store", "Ist_StoreG"):
                if not _expr_is_stack(stmt.addr, stack_regs, sp_tmps):
                    return False, f"writes non-stack memory at {block_addr:#x}", [], 0
            elif tag == "Ist_Exit":
                branch_targets.append(stmt.dst.value & ~1)

        if jumpkind == "Ijk_Boring":
            if irsb.next.tag == "Iex_Const":
                # Direct branch: a constant target outside the function is a tail
                # call, e.g. `b.w read_from_input` (the Ijk_Call check misses it
                # because a tail call is Ijk_Boring). A branch into a pure
                # intrinsic hook (TT/SG) stays within the leaf.
                branch_targets.append(irsb.next.con.value & ~1)
            else:
                # Indirect branch: fine only if it is a resolved jump table (an
                # internal tbb/tbh/ldr-pc switch). Otherwise it is an indirect tail
                # call or unresolved branch, e.g. `bx r3` to a function pointer.
                insn_addrs = block.instruction_addrs
                jump_addr = (insn_addrs[-1] if insn_addrs else block_addr) & ~1
                is_switch = (block_addr & ~1) in jump_table_targets or jump_addr in jump_table_targets or _indirect_branch_is_switch(project, block)
                if not is_switch:
                    return False, f"indirect branch (tail call / unresolved) at {block_addr:#x}", [], 0
                fanout = _table_branch_fanout(project, func, block)
                if fanout:
                    switch_fanout[block_addr & ~1] = fanout

        for target in branch_targets:
            if target not in func_block_set and not _is_pure_intrinsic(project, target):
                return False, f"tail-calls / branches out of function to {target:#x} at {block_addr:#x}", [], 0

        if jumpkind == "Ijk_Ret":
            # Merge at the return *instruction*, not the block entry: by then the
            # return value is final and callee-saved registers are restored.
            insn_addrs = block.instruction_addrs
            ret_addrs.append(insn_addrs[-1] if insn_addrs else block_addr)
        elif jumpkind == "Ijk_NoDecode":
            # VEX hit an instruction it cannot decode. If it is a pure Cortex-M
            # intrinsic hook (e.g. TT/SG), it is part of the leaf; otherwise we
            # cannot vouch for the function.
            bad_addr = block.instruction_addrs[-1] if block.instruction_addrs else block_addr
            if not _is_pure_intrinsic(project, bad_addr):
                return False, f"undecodable instruction (not a pure intrinsic) at {bad_addr:#x}", [], 0

    if not ret_addrs:
        return False, "never returns (no Ijk_Ret block)", [], 0

    # Rank by CFG fan-out: the number of extra successor edges across the
    # function. For each block the fan-out is the larger of its CFG out-degree and
    # its jump-table target count (when it ends in a tbb/tbh/ldr-pc switch), so a
    # multi-way branch is counted by its real table size even when the CFG
    # under-resolves it because nearby instructions are hooked. The fan-out of the
    # functions this one calls is added on, so a caller ranks above its callees
    # (merging at its return collapses its own branches plus theirs).
    graph = func.graph
    own_branch_count = 0
    for node in graph.nodes:
        key = node.addr & ~1
        fan_out = max(graph.out_degree(node), jump_table_targets.get(key, 0), switch_fanout.get(key, 0))
        own_branch_count += max(0, fan_out - 1)

    return True, "accepted", ret_addrs, own_branch_count + called_branch_count


def _analyze_function(project, func, sp_offset, max_blocks, jump_table_targets=None, max_depth=MAX_CALL_DEPTH):
    """
    Inspect a function. Returns ((start_addr, [merge_addrs], branch_count), reason)
    if it is a pure, returning function (a leaf, or one that only calls other pure
    functions within `max_depth` levels), else (None, reason).
    """
    if jump_table_targets is None:
        jump_table_targets = {}

    ok, reason, ret_addrs, branch_count = _scan_function(project, func, sp_offset, max_blocks, jump_table_targets, max_depth, memo={})
    if not ok:
        return None, reason

    return (func.addr, sorted(set(ret_addrs)), branch_count), "accepted"


def find_merge_candidates(project, min_branches=MIN_BRANCHES, max_candidates=MAX_CANDIDATES, max_blocks=MAX_BLOCKS, max_depth=MAX_CALL_DEPTH):
    """
    Scan `project.kb.functions` for pure, branchy leaf functions worth merging.

    Returns a list of (start_addr, merge_addrs, func_name, branch_count) tuples,
    ranked by branch count (most branches first), capped at `max_candidates`.
    Per-function accept/reject reasons are logged at DEBUG level.
    """
    built_cfg = False
    functions = project.kb.functions
    if not functions:
        # Some targets (e.g. SGX enclave dumps) reach here without a CFG, since
        # only the ARM hooker runs CFGFast. Build it now so detection works there.
        logger.info("No functions in the knowledge base yet; running CFGFast for merge-point detection.")
        try:
            # Skip indirect-jump resolution: it runs VSA, which cannot handle the
            # taint annotations already present on enclave memory at this point.
            project.analyses.CFGFast(resolve_indirect_jumps=False)
        except Exception as e:
            logger.warning(f"CFGFast failed ({e}); skipping auto merge-point detection.")
            return []
        built_cfg = True
        functions = project.kb.functions
        if not functions:
            _discard_cfg(project)
            logger.warning("Still no functions after CFGFast; skipping auto merge-point detection.")
            return []

    try:
        return _scan_functions(project, functions, min_branches, max_candidates, max_blocks, max_depth)
    finally:
        if built_cfg:
            # We only built the CFG to find merge points. Drop it again so it does
            # not change later behaviour (e.g. angr's disassembly renderer takes a
            # buggy graph path when a CFG is present for an enclave dump).
            _discard_cfg(project)


def _discard_cfg(project):
    try:
        project.kb.cfgs.cfgs.clear()
        project.kb.functions.clear()
    except Exception as e:
        logger.debug(f"Could not discard temporary CFG: {e}")


def _function_name(project, func):
    """
    Resolve a function's name. For enclave dumps the angr loader has no symbols
    (names are `sub_<addr>`), but Pandora's SymbolManager holds the names from the
    SDK ELF / .so, so prefer those.
    """
    try:
        from sdks.SymbolManager import SymbolManager

        name = SymbolManager().get_symbol_exact(func.addr)
        if name:
            return name
    except (Exception, SystemExit) as e:
        # SystemExit: SymbolManager.__init__ calls exit() if it is not yet set up;
        # name resolution must never take down the run, so fall back to the name
        # from the angr loader.
        logger.debug(f"Could not resolve symbol for {func.addr:#x}: {e}")
    return func.name


def _scan_functions(project, functions, min_branches, max_candidates, max_blocks, max_depth):
    sp_offset = project.arch.sp_offset

    # Resolved jump tables (tbb/tbh/ldr-pc switches), mapping the jump site to its
    # number of distinct targets. Used both to tell an internal multi-way branch
    # apart from an indirect tail call (`bx reg`) and to rank its fan-out by the
    # real table size, which the CFG can under-count when nearby code is hooked.
    cfg_model = project.kb.cfgs.get_most_accurate()
    jump_tables = getattr(cfg_model, "jump_tables", None) or {}
    jump_table_targets: dict[int, int] = {}
    for addr, ij in jump_tables.items():
        targets = getattr(ij, "resolved_targets", None) or getattr(ij, "jumptable_entries", None) or ()
        count = len(set(targets))
        for key in (addr, getattr(ij, "addr", None), getattr(ij, "ins_addr", None)):
            if key is not None:
                jump_table_targets[key & ~1] = max(jump_table_targets.get(key & ~1, 0), count)

    candidates = []
    for func in functions.values():
        try:
            result, reason = _analyze_function(project, func, sp_offset, max_blocks, jump_table_targets, max_depth)
        except Exception as e:  # lifting/analysis can fail on data or odd blocks
            logger.debug(f"merge-point scan: {func.name} @ {func.addr:#x}: analysis error: {e}")
            continue

        if result is None:
            logger.debug(f"merge-point scan: {func.name} @ {func.addr:#x}: rejected ({reason})")
            continue

        start_addr, merge_addrs, branch_count = result
        if branch_count < min_branches:
            logger.debug(f"merge-point scan: {func.name} @ {func.addr:#x}: too few branches ({branch_count} < {min_branches})")
            continue

        name = _function_name(project, func)
        logger.debug(f"merge-point scan: {name} @ {func.addr:#x}: candidate ({branch_count} branches, {len(func.block_addrs_set)} blocks)")
        candidates.append((branch_count, start_addr, merge_addrs, name))

    candidates.sort(key=lambda c: c[0], reverse=True)
    return [(start, merges, name, branches) for (branches, start, merges, name) in candidates[:max_candidates]]


class ManualMerger(ExplorationTechnique):
    def __init__(self, start_addr, merge_addrs, wait_counter=10, prune=True, name=None):
        super().__init__()
        self.start_address = start_addr
        self.merge_addresses = merge_addrs
        self.wait_counter_limit = wait_counter
        self.prune = prune
        self.name = name
        self.stashes: dict[str, int] = {}  # stash name -> wait counter

        self.label = f"{name} @ {start_addr:#x}" if name else f"{start_addr:#x}"
        # A per-instance child logger so each merger's lines are attributable to
        # the function it merges (the logger name carries the label).
        self.logger = logger.getChild(f"{name}@{start_addr:#x}" if name else f"{start_addr:#x}")
        self.logger.info(f"Initialized ManualMerger with merge_addrs={[hex(addr) for addr in self.merge_addresses]}, wait_counter={self.wait_counter_limit}, prune={self.prune}")

    def step(self, simgr, stash="active", **kwargs):
        for src_stash in self.stashes.keys():
            # ha ha, very funny, if this is being run on a single-step basis our filter probably misfired
            if len(simgr.stashes[src_stash]) == 1 and len(simgr.stashes[stash]) == 0:
                simgr = simgr.move(src_stash, stash)

        # perform all our analysis as a post-mortem on a given step
        stop_points = kwargs.pop("extra_stop_points", set())
        for addr in self.merge_addresses:
            stop_points.add(addr)
        simgr = simgr.step(stash=stash, extra_stop_points=stop_points, **kwargs)

        # mark states in the merge range as "sticky" to prevent them from being deferred by other techniques (e.g. DFS)
        for state in simgr.stashes[stash]:
            if state.addr == self.start_address:
                state.globals["sticky"] = True

        # do filtering
        new_stash = []
        for state in simgr.stashes[stash]:
            if state.addr in self.merge_addresses:
                # Group states by return address and call history
                return_addr = state.callstack.ret_addr

                # Get addresses in history up to latest hit of self.start_address
                history_addrs = state.history.bbl_addrs
                last_index = next((i for i, addr in enumerate(reversed(history_addrs)) if addr == self.start_address), 0)
                history_hash = hash(tuple(history_addrs)[: -last_index - 1])

                stash_name = f"manualmerge_waiting_ret_{return_addr:#x}_history_{history_hash:x}"

                self.stashes[stash_name] = 0
                simgr.stashes[stash_name].append(state)
            else:
                new_stash.append(state)
        simgr.stashes[stash][:] = new_stash

        for src_stash in self.stashes.keys():
            # nothing to do if there's no states waiting
            if len(simgr.stashes[src_stash]) == 0:
                continue

            # Keep waiting (and reset the counter) while states that will still
            # reach this merge point are in flight: either exploring this function
            # or parked inside one of its callees by an inner merger. Without this a
            # nested inner merger (e.g. cmse_check_address_range inside
            # tfm_hal_memory_check) only releases its states after its own wait, by
            # which time this merger would already have merged a partial set.
            if self._has_pending_inflow(simgr, stash):
                self.stashes[src_stash] = 0
                continue

            # tick the counter
            self.stashes[src_stash] += 1

            # see if it's time to merge (out of active or hit wait limit)
            if len(simgr.stashes[stash]) != 0 and self.stashes[src_stash] < self.wait_counter_limit:
                continue

            # only both merging if, you know, there's actually states to merge
            if len(simgr.stashes[src_stash]) == 1:
                for state in simgr.stashes[src_stash]:
                    state.globals["sticky"] = False
                simgr.move(src_stash, stash)
                continue

            # Merge states and add to active stash
            grouped_states = self.group_states_by_return_value(simgr.stashes[src_stash])

            self.logger.debug(f"Merging {len(simgr.stashes[src_stash])} states with return values {[self.get_return_value(state) for state in simgr.stashes[src_stash]]}")
            self.logger.info(f"Merging {len(simgr.stashes[src_stash])} states. Resulting groups: { {ret_val: len(states) for ret_val, states in grouped_states.items()} }")
            self.logger.debug(f"All stashes before merging: { {s: len(simgr.stashes[s]) for s in simgr.stashes} }")

            merged_states = []
            for states in grouped_states.values():
                merged_state = self.merge_states_with_same_return(states)
                if merged_state is not None:
                    # Clear "sticky" flag to allow other techniques to work with the merged state
                    merged_state.globals["sticky"] = False
                    simgr.stashes[stash].append(merged_state)
                    merged_states.append(merged_state)

            # Clear the waiting stash
            simgr.stashes[src_stash] = []

        # Clear empty stashes
        for src_stash in list(self.stashes.keys()):
            if len(simgr.stashes[src_stash]) == 0:
                del self.stashes[src_stash]
                del simgr.stashes[src_stash]

        return simgr

    def _state_inside_my_function(self, state):
        """True if the state is currently executing this merger's function or one
        of its callees, i.e. it has not yet reached (or returned past) the merge
        point. Detected by the function's entry appearing in the callstack."""
        start = self.start_address & ~1
        try:
            return any(((frame.func_addr or 0) & ~1) == start for frame in state.callstack)
        except Exception:
            return False

    def _has_pending_inflow(self, simgr, active_stash):
        """True if some state that will still reach this merge point is in flight:
        an active state executing this function, or a state another (inner) merger
        is holding inside one of this function's callees."""
        for state in simgr.stashes[active_stash]:
            if self._state_inside_my_function(state):
                return True
        for stash_name, states in simgr.stashes.items():
            # Only other mergers' waiting stashes; our own arrivals don't count.
            if stash_name == active_stash or stash_name in self.stashes:
                continue
            if not stash_name.startswith("manualmerge_waiting"):
                continue
            for state in states:
                if self._state_inside_my_function(state):
                    return True
        return False

    @staticmethod
    def get_return_value(state: angr.SimState):
        """Read the architecture's return register (e.g. r0 on ARM, rax on AMD64)."""
        return state.registers.load(state.arch.ret_offset, state.arch.bytes)

    def group_states_by_return_value(self, states):
        """
        Group states by their return value (arch return register, e.g. r0 or rax).

        Args:
            states: List of states to group

        Returns:
            Dictionary mapping return values to lists of states
        """
        grouped: dict[int, list[angr.SimState]] = defaultdict(list)

        for state in states:
            ret_val = self.get_return_value(state)

            # Try to get concrete return value
            if not state.solver.symbolic(ret_val):
                ret_val = state.solver.eval(ret_val)

            grouped[ret_val].append(state)

        return grouped

    def merge_states_with_same_return(self, states: list[angr.SimState]) -> angr.SimState | None:
        """
        Merge states that share the same (concrete) return value into one.

        The states are grouped by `r0`, so they already agree on the return
        register. Every *other* register that differs between them is replaced by
        a guarded value `ITE(g_1, v_1, ITE(g_2, v_2, ... v_n))`, where `g_i` is
        state i's distinguishing path constraint and `v_i` its value for that
        register. This keeps a second return register (e.g. `r1` for a 64-bit or
        struct return, or `s0`/`d0` for a float) correct without having to know
        the function's return width: if the register is actually dead it is
        overwritten before any read, and if it is live the guarded value selects
        the right one per path. Registers that are identical across the group
        (callee-saved registers, SP, ...) are left untouched, and memory is not
        merged (the merge-point functions write nothing but their own, now-dead,
        stack frame).

        The guards are mutually exclusive (sibling paths diverged at some branch)
        and exhaustive within the merged state (its constraint is the disjunction
        of the guards over the common prefix), so the selection is unambiguous.
        """
        if not states:
            return None

        if len(states) == 1:
            return states[0]

        common_constraints = set.intersection(*(set(state.solver.constraints) for state in states))

        # The distinguishing constraint set of each state (its path constraints
        # beyond the common prefix). An empty set means the state is as general
        # as the common prefix; order such states last so they act as the `else`.
        unique_constraints = [set(state.solver.constraints) - common_constraints for state in states]
        order = sorted(range(len(states)), key=lambda i: len(unique_constraints[i]) == 0)
        states = [states[i] for i in order]
        unique_constraints = [unique_constraints[i] for i in order]

        # Per-state guard ASTs (True for a state with no distinguishing constraint).
        guards = [claripy.And(*uc) if uc else claripy.true for uc in unique_constraints]

        merged_state = states[0]

        # Guarded-ITE merge of every register that differs across the group. Dedup
        # by VEX offset (taking the widest register) so overlapping aliases/
        # subregisters are handled once.
        reg_widths: dict[int, int] = {}
        for reg in merged_state.arch.register_list:
            if reg.vex_offset is None or reg.name not in ["r0", "r1", "r2", "r3", "s0", "d0"]:
                continue
            reg_widths[reg.vex_offset] = max(reg_widths.get(reg.vex_offset, 0), reg.size)

        # Never merge the program counter: states grouped from different return
        # sites would get a multi-valued PC that the engine cannot concretize on
        # the next step. Keeping states[0]'s PC is correct -- every state in the
        # group returns to the same caller address.
        ip_offset = merged_state.arch.ip_offset

        for offset, size in reg_widths.items():
            if offset == ip_offset:
                continue
            values = [state.registers.load(offset, size) for state in states]
            # Compare structurally via the AST hash. Avoid claripy's `.identical()`,
            # which routes through a solver backend (VSA) that cannot handle
            # Pandora's taint annotations on register values.
            first_hash = hash(values[0])
            if all(hash(v) == first_hash for v in values[1:]):
                continue  # identical across the group (e.g. callee-saved) -> keep as is

            # Build ITE(g_0, v_0, ITE(g_1, v_1, ... v_{n-1})); the last state is the else.
            merged_value = values[-1]
            for guard, value in zip(reversed(guards[:-1]), reversed(values[:-1])):
                merged_value = claripy.If(guard, value, merged_value)
            merged_state.registers.store(offset, merged_value)

        # Replace the path constraints with the common prefix plus the disjunction
        # of the per-state guards. If some state had no distinguishing constraint,
        # the union is exactly the common prefix, so no extra disjunction is added.
        parts = [claripy.And(*uc) for uc in unique_constraints if uc]
        extra = [claripy.Or(*parts)] if len(parts) == len(states) else []
        merged_state.solver.reload_solver(list(common_constraints) + extra)

        return merged_state
