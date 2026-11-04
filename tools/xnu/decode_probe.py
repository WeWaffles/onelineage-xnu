#!/usr/bin/env python3
"""Decode an m468-class ring and resolve fault PCs to kernel symbols.

Gates: a ring is usable only if it is a full-size read (>= 1 MiB), carries
exactly one LE 0xAA13, and contains XNUKRN1.  Anything else is reported as no
measurement rather than decoded.

Symbol resolution note: the previous resolver required (pc - sym) to be a
multiple of the page size.  That is wrong for a normal return address, where
pc = symbol + offset, so it could never match a real PC.  This resolves the
nearest symbol at or below the PC within a bounded window and reports the
offset, stating explicitly that the offset is only exact when the kernel runs
unslid.
"""
from __future__ import annotations
import argparse, hashlib, pathlib, re, struct, subprocess, sys

AA = (0xAA13).to_bytes(8, "little")
PROOF = 0x313053534E584C4F
SYS = 0x4F4C584E
VALID = 0x44494C4156     # "VALID", written last into every mirror record
EXC_MAGIC = 0x4F4C584E   # what sleh.c writes into every 0x9000/0x9200 record
MIN_BYTES = 2_000_000
WINDOW = 0x40000


def fresh_ring(path: pathlib.Path) -> bool:
    if not path.exists():
        return False
    d = path.read_bytes()
    return len(d) >= MIN_BYTES and d.count(AA) == 1 and b"XNUKRN1" in d


def candidates(outdir: pathlib.Path) -> list[pathlib.Path]:
    return sorted(outdir.glob("ring_*.bin")) + sorted(outdir.glob("late.bin"))


def load_symbols(kernel: pathlib.Path) -> list[tuple[int, str]]:
    # Any defined symbol counts: this image reports section symbols as "S",
    # and filtering on t/T/w/W alone yielded zero symbols and silently broke
    # resolution.  Undefined ("U") entries have no address and are skipped.
    out = subprocess.run(["nm", "-n", str(kernel)], capture_output=True, text=True).stdout
    tab = []
    for line in out.splitlines():
        f = line.split()
        if len(f) == 3 and len(f[1]) == 1 and f[1] not in "Uu":
            try:
                addr = int(f[0], 16)
            except ValueError:
                continue
            if addr:
                tab.append((addr, f[2]))
    return tab


def resolve_pc(pc: int, tab: list[tuple[int, str]]) -> tuple[str, int] | None:
    best = None
    for addr, name in tab:
        d = pc - addr
        if 0 <= d < WINDOW and (best is None or addr > best[0]):
            best = (addr, name)
    return None if best is None else (best[1], pc - best[0])


def decode(d: bytes) -> dict | None:
    # A real ring always carries the marker at or after RING_OFFSET; a buffer
    # where it appears earlier cannot be decoded with those offsets, and
    # silently reading shifted fields is worse than refusing (m468 prep: a
    # 7-byte slice assignment shrank a test buffer by one byte and produced a
    # base of -1, which read 0x9000 out of misaligned bytes).
    off = d.find(AA)
    base = off - 0x1780
    if off < 0 or base < 0:
        return None
    g = lambda o: struct.unpack_from("<Q", d, base + o)[0]
    res = {"base": base, "exc": [], "exc2": [], "sys": [], "mmap": [], "slots": {}}
    for n in (12, 13, 14, 15, 17, 20, 21, 22, 23, 24, 25):
        b = 0x600 + n * 0x100
        if g(b) == PROOF:
            res["slots"][n] = (g(b+0x18), g(b+0x20), g(b+0x28), g(b+0x30), g(b+0x38))
    # Two writers share this layout shape but not the same slots any more:
    # 0x9000 = legacy unfiltered record (all sync exceptions, no PC) and
    # 0x9200 = m468 filtered record (EC != 0x15 only, carries PC).  Both write
    # magic EXC_MAGIC; PROOF is accepted as well so rings from older builds
    # still decode.
    for k in range(4):
        b = 0x9000 + k * 0x40
        if g(b) in (EXC_MAGIC, PROOF):
            res["exc"].append(dict(esr=g(b+8), far=g(b+16), pc=g(b+24),
                                   user=g(b+32), ec=g(b+40), thread=g(b+48)))
    res["exc_count"] = g(0x9100)
    for k in range(4):
        b = 0x9200 + k * 0x40
        if g(b) in (EXC_MAGIC, PROOF):
            res["exc2"].append(dict(esr=g(b+8), far=g(b+16), pc=g(b+24),
                                    user=g(b+32), ec=g(b+40), thread=g(b+48)))
    res["exc2_count"] = g(0x9300)
    for k in range(8):
        b = 0x8400 + k * 0x38
        if g(b) == SYS:
            res["sys"].append(dict(code=g(b+8), err=g(b+16), pid=g(b+24),
                                   arg0=g(b+32), afterlast=g(b+40), proc=g(b+48)))
    for k in range(4):
        b = 0x8e00 + k * 0x40
        if g(b) == SYS:
            res["mmap"].append(dict(errno=g(b+16), rval64=g(b+32), afterlast=g(b+56)))
    #
    # Fixed-slot mirrors that sleh_synchronous rewrites on every synchronous
    # exception, so they survive the log ring rotating.  A slot counts only
    # when both its magic and its trailing VALID word are present; anything
    # else is log text and is reported absent rather than decoded.
    #
    m: dict = {}
    if g(0x9110) == SYS and g(0x9130) == VALID:
        m["exec"] = dict(pid=g(0x9118), entry=g(0x9120), refreshes=g(0x9128))
    if g(0x9140) == SYS and g(0x9158) == VALID:
        m["enter"] = dict(pid=g(0x9148), path8=g(0x9150))
    if g(0x9160) == SYS and g(0x9188) == VALID:
        m["enters"] = dict(total=g(0x9168), pid1=g(0x9170),
                           pid2=g(0x9178), other=g(0x9180))
    if g(0x9190) == SYS and g(0x91e0) == VALID:
        m["counts"] = dict(loads=g(0x9198), syscalls=g(0x91a0),
                           sys_pid1=g(0x91a8), sys_pid2=g(0x91b0),
                           sys_other=g(0x91b8), writes=g(0x91c0),
                           w_pid1=g(0x91c8), w_pid2=g(0x91d0),
                           w_zero=g(0x91d8))
    if g(0x9400) == SYS and g(0x9430) == VALID:
        fdlen = g(0x9410)
        m["last_write"] = dict(pid=g(0x9408), fd=fdlen & 0xFFFFFFFF,
                               length=fdlen >> 32, result=g(0x9418),
                               error=g(0x9420), seq=g(0x9428))
    if g(0x9440) == SYS and g(0x9460) == VALID:
        m["last_syscall"] = dict(pid=g(0x9448), code=g(0x9450), seq=g(0x9458))
    entries = []
    for si in range(4):
        so = 0x9480 + si * 0x20
        if g(so) == SYS and g(so + 0x18) == VALID:
            entries.append(dict(pid=g(so + 8), path8=g(so + 0x10)))
    m["enter_slots"] = entries
    m["enter_count"] = g(0x9520)
    if g(0x9598) == 0x54524157:
        m["wait_enter"] = dict(calls=g(0x9580), pid=g(0x9588),
                               arg0=g(0x9590))
    if g(0x95b8) == 0x54495845:
        m["exit_enter"] = dict(calls=g(0x95a0), pid=g(0x95a8),
                               status=g(0x95b0))
    if g(0x95c0) == 0x49584550:
        m["proc_exit"] = dict(pid=g(0x95c8), tid=g(0x95d0))
    if g(0x95e0) == 0x424d4f5a:
        m["zombie"] = dict(pid=g(0x95e8), ppid=g(0x95f0),
                           p_stat=g(0x95f8))
    if g(0x9600) == 0x454b4157:
        m["wake_done"] = dict(pid=g(0x9608), ppid=g(0x9610))
    if g(0x9620) == 0x50454c53:
        m["sleep_addr"] = dict(addr=g(0x9628), pid=g(0x9630))
    if g(0x9640) == 0x52444157:
        m["wake_addr"] = dict(addr=g(0x9648))
    trace = []
    for base, magic, name, aoff, boff in (
            (0x9660, 0x50454c53, "sleep", 0x9668, 0x9670),
            (0x9680, 0x57415557, "wake", 0x9688, 0x9690),
            (0x96a0, 0x544552, "return", 0x96a8, 0x96b0)):
        if g(base + 0x18) == magic:
            trace.append(dict(seq=g(base), event=name, a=g(aoff), b=g(boff)))
    if trace:
        m["trace"] = sorted(trace, key=lambda e: e["seq"])
    if g(0x9540) == SYS and g(0x9570) == VALID:
        m["wait"] = dict(pid=g(0x9548), reaped=g(0x9550), status=g(0x9558),
                          error=g(0x9560), calls=g(0x9568))
    res["mirrors"] = m
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ring-dir", type=pathlib.Path, required=True)
    ap.add_argument("--jump-log", type=pathlib.Path, default=pathlib.Path("/tmp/m468_drv.log"))
    ap.add_argument("--capture-log", type=pathlib.Path, default=pathlib.Path("/tmp/m468_cap.log"))
    ap.add_argument("--kernel", type=pathlib.Path,
                    default=pathlib.Path("build/xnu-src/source/BUILD/obj/DEVELOPMENT_ARM64_SWEET/kernel.development.sweet"))
    a = ap.parse_args()

    jumped = a.jump_log.exists() and "jumping" in a.jump_log.read_text(errors="replace")
    if not jumped:
        print("OUTCOME=NO_JUMP (driver log has no jumping line; nothing was measured)")
        return 0
    good = [p for p in candidates(a.ring_dir) if fresh_ring(p)]
    if not good:
        print("OUTCOME=JUMP_NO_FRESH_RING (jump issued, no full-size ring with LE 0xAA13 and XNUKRN1)")
        for p in candidates(a.ring_dir):
            d = p.read_bytes()
            print(f"  rejected {p.name}: bytes={len(d)} AA13={d.count(AA)} XNUKRN1={d.count(b'XNUKRN1')}")
        return 0
    p = good[-1]
    d = p.read_bytes()
    print(f"OUTCOME=FRESH_RING {p.name} sha256={hashlib.sha256(d).hexdigest()[:12]} bytes={len(d)}")
    r = decode(d)
    if r is None:
        print("OUTCOME=FRESH_RING_UNUSABLE (LE 0xAA13 sits before the ring offset; "
              "refusing to decode shifted fields)")
        return 0
    for n, v in sorted(r["slots"].items()):
        print(f"  slot[{n}] stage={v[0]:#x} a={v[1]:#x} b={v[2]:#x} c={v[3]:#x} d={v[4]:#x}")
    print(f"  exc counter: {r['exc_count']}")
    for i, e in enumerate(r["exc"]):
        print(f"  exc[{i}] esr={e['esr']:#x} ec={e['ec']} far={e['far']:#x} pc={e['pc']:#x} user={e['user']}")
    print(f"  filtered exc counter (0x9300): {r['exc2_count']}")
    for i, e in enumerate(r["exc2"]):
        print(f"  exc2[{i}] esr={e['esr']:#x} ec={e['ec']} far={e['far']:#x} pc={e['pc']:#x} user={e['user']}")
    for i, s in enumerate(r["sys"]):
        print(f"  sys[{i}] code={s['code']} err={s['err']} pid={s['pid']} arg0={s['arg0']} afterlast={s['afterlast']}")
    for i, m in enumerate(r["mmap"]):
        print(f"  mmapret[{i}] errno={m['errno']} rval64={m['rval64']:#x} afterlast={m['afterlast']}")

    def path_str(w: int) -> str:
        raw = w.to_bytes(8, "little")
        return "".join(chr(b) if 32 <= b < 127 else "." for b in raw)

    mm = r.get("mirrors", {})
    print(f"  mirrors present: {', '.join(sorted(mm)) or 'none'}")
    if "exec" in mm:
        e = mm["exec"]
        print(f"  mirror exec: pid={e['pid']} entry={e['entry']:#x} refreshes={e['refreshes']}")
    if "enter" in mm:
        e = mm["enter"]
        print(f"  mirror enter: pid={e['pid']} path8={e['path8']:#x} '{path_str(e['path8'])}'")
    if "enters" in mm:
        e = mm["enters"]
        print(f"  execs entered: total={e['total']} pid1={e['pid1']} pid2={e['pid2']} other={e['other']}")
    if "counts" in mm:
        e = mm["counts"]
        print(f"  execs loaded: {e['loads']}")
        print(f"  syscalls: total={e['syscalls']} pid1={e['sys_pid1']} pid2={e['sys_pid2']} other={e['sys_other']}")
        print(f"  writes: total={e['writes']} pid1={e['w_pid1']} pid2={e['w_pid2']} zero_len={e['w_zero']}")
    if "last_write" in mm:
        e = mm["last_write"]
        print(f"  last write: pid={e['pid']} fd={e['fd']} len={e['length']} "
              f"result={e['result']} err={e['error']} seq={e['seq']}")
    if "last_syscall" in mm:
        e = mm["last_syscall"]
        print(f"  last syscall: pid={e['pid']} code={e['code']} seq={e['seq']}")
    if "wait" in mm:
        e = mm["wait"]
        print(f"  wait4: pid={e['pid']} reaped={e['reaped']} status={e['status']} "
              f"err={e['error']} calls={e['calls']}")
    if "wait_enter" in mm:
        e = mm["wait_enter"]
        print(f"  wait4 entered: calls={e['calls']} pid={e['pid']} "
              f"arg0={e['arg0']:#x}")
    if "exit_enter" in mm:
        e = mm["exit_enter"]
        print(f"  exit entered: calls={e['calls']} pid={e['pid']} "
              f"status={e['status']}")
    if "proc_exit" in mm:
        e = mm["proc_exit"]
        print(f"  proc_exit entered: pid={e['pid']} tid={e['tid']}")
    if "zombie" in mm:
        e = mm["zombie"]
        print(f"  zombie before wakeup: pid={e['pid']} ppid={e['ppid']} "
              f"p_stat={e['p_stat']}")
    if "wake_done" in mm:
        e = mm["wake_done"]
        print(f"  wakeup returned: pid={e['pid']} ppid={e['ppid']}")
    if "sleep_addr" in mm:
        e = mm["sleep_addr"]
        print(f"  wait4 slept on: {e['addr']:#x} (pid={e['pid']})")
    if "wake_addr" in mm:
        e = mm["wake_addr"]
        print(f"  exit woke on:   {e['addr']:#x}")
    if "sleep_addr" in mm and "wake_addr" in mm:
        same = mm["sleep_addr"]["addr"] == mm["wake_addr"]["addr"]
        print(f"  sleep/wake addresses match: {same}")
    for e in mm.get("trace", []):
        print(f"  seq {e['seq']}: {e['event']:6} a={e['a']:#x} b={e['b']:#x}")
    if mm.get("enter_slots"):
        print(f"  exec entries recorded: {mm['enter_count']}")
        for i, s in enumerate(mm["enter_slots"]):
            print(f"  enter[{i}] pid={s['pid']} path8={s['path8']:#x} '{path_str(s['path8'])}'")

    recs = [("exc", e) for e in r["exc"]] + [("exc2", e) for e in r["exc2"]]
    if recs:
        if not a.kernel.exists():
            print("  symbol resolution: kernel image missing")
        else:
            tab = load_symbols(a.kernel)
            for i, e in recs:
                hit = resolve_pc(e["pc"], tab)
                if hit:
                    print(f"  resolved {i} pc={e['pc']:#x} -> {hit[0]}+{hit[1]:#x} "
                          f"(offset exact only if the kernel runs unslid)")
                else:
                    print(f"  resolved {i} pc={e['pc']:#x} -> no symbol within {WINDOW:#x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
