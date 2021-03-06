import dataclasses
import logging
import re
import statistics
import typing

from harness import syscall_info

_SYSCALLS = {}
LOG = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True, order=True)
class Syscall:
    nr: int
    name: str

    def __post_init__(self):
        _SYSCALLS[self.nr] = self

    @classmethod
    def from_nr(cls, nr):
        if nr in _SYSCALLS:
            return _SYSCALLS[nr]
        return cls(nr, syscall_info.from_nr(nr))


@dataclasses.dataclass
class SyscallInvocation:
    syscall: Syscall
    start_ns: int
    duration_ns: int
    ustack_id: int
    userspace_before: int = -1
    userspace_after: int = -1
    ustack: typing.Tuple[str] = None
    ustack2: typing.Tuple['StackFrame'] = None
    end_ns: int = -1
    syscall_loc: typing.Tuple[Syscall, int] = None

    def __post_init__(self):
        self.end_ns = self.start_ns + self.duration_ns
        self.syscall_loc = (self.syscall, self.ustack_id)


@dataclasses.dataclass
class SpanInfo:
    pairs: typing.List[
        typing.Tuple[
            SyscallInvocation,
            SyscallInvocation,
        ],
    ] = dataclasses.field(
        default_factory=list,
    )

    def quantiles(self, n=10):
        return statistics.quantiles(
            (p[0].userspace_after for p in self.pairs),
            n=n,
        )

    def mean_median(self):
        intervals = tuple(
            i1.userspace_after
            for i1, _ in self.pairs
        )
        return (
            statistics.mean(intervals),
            statistics.median(intervals),
        )


_PAT_STACK_FRAME = r'([a-f0-9]+)\s+(0?x?[_a-zA-Z.][_a-zA-Z.0-9]*?)(\+\d+)?\s*\((.*?)\)'


@dataclasses.dataclass(frozen=True)
class StackFrame:
    addr: int
    func: str
    off: int
    module: str
    tag: object

    @classmethod
    def from_stack_line(cls, row, tag):
        match = re.match(
            _PAT_STACK_FRAME,
            row.strip(),
        )

        addr, func, off, mod = match.groups()
        addr = int(addr, 16)
        if off is not None:
            off = int(off)
        return cls(addr, func, off, mod, tag)



@dataclasses.dataclass
class ThreadTrace:
    invocations: typing.List[SyscallInvocation] = dataclasses.field(
        default_factory=list,
    )
    ustacks: typing.Dict[int, typing.Tuple[str]] = dataclasses.field(
        default_factory=dict,
    )
    ustacks2: typing.Dict[int, typing.Tuple[str]] = dataclasses.field(
        default_factory=dict,
    )
    userspace_spans: typing.Dict[
        typing.Tuple[
            typing.Tuple[Syscall, int],
            typing.Tuple[Syscall, int],
        ],
        SpanInfo,
    ] = dataclasses.field(default_factory=dict)

    def calculate_userspace_times(self):
        for a, b in zip(self.invocations, self.invocations[1:]):
            a.userspace_after = b.start_ns - a.end_ns
            b.userspace_before = a.userspace_after

    @property
    def duration(self):
        return (self.invocations[-1].end_ns - self.invocations[0].start_ns)

    @property
    def average_interval(self):
        return self.duration / len(self.invocations)

    @property
    def userspace_time_quantiles(self):
        return statistics.median(
            (i.userspace_after for i in self.invocations[:-1]),
        ), statistics.median(
            (i.duration_ns for i in self.invocations[:-1])
        )


@dataclasses.dataclass
class Trace:
    threads: typing.Dict[int, ThreadTrace] = dataclasses.field(
        default_factory=dict,
    )


def build_trace(f):
    trace = Trace()
    headers = next(f).strip().split(',')

    def _to_row(line):
        line = line.strip()
        return dict(zip(headers, (int(e, 16) for e in line.split(',')[:-1])))

    def _add_invocation(row):
        row = _to_row(row)
        try:
            sc = Syscall.from_nr(row['sysnr'])
        except KeyError:
            return
        sci = SyscallInvocation(
            syscall=sc,
            start_ns=row['tbegin'],
            duration_ns=row['dur'],
            ustack_id=row['ustack'],
            ustack=trace.threads[row['tid']].ustacks[row['ustack']],
            ustack2=trace.threads[row['tid']].ustacks2[row['ustack']],
        )
        tid = row['tid']
        trace.threads.setdefault(tid, ThreadTrace()).invocations.append(sci)

    def _add_ustack(stack_id, tid, sysnr):
        LOG.debug('ustack %d', stack_id)
        stack = []
        for row in f:
            row = row.strip()
            if not row:
                continue
            if row == 'ustackend':
                break
            stack.append(row)
        trace.threads.setdefault(tid, ThreadTrace()).ustacks[stack_id] = tuple(stack)
        trace.threads[tid].ustacks2[stack_id] = [
            StackFrame(
                addr=0,
                func=syscall_info.from_nr(sysnr),
                off=0,
                module='[kernel]',
                tag=stack_id,
            ),
        ] + [
            StackFrame.from_stack_line(f, tag=stack_id) for f in stack
        ]


    for row in f:
        if not row.strip():
            continue
        if row.startswith('i:'):
            _add_invocation(row[2:])
        if row.startswith('ustack:'):
            _, nr, tid, sysnr = row.strip().split()
            nr = int(nr)
            tid = int(tid)
            sysnr = int(sysnr)
            _add_ustack(nr, tid, sysnr)


    for tid, thread in trace.threads.items():
        # for inv in thread.invocations:
        #     inv.ustack = thread.ustacks[inv.ustack_id]

        for inv1, inv2 in zip(thread.invocations, thread.invocations[1:]):
            thread.userspace_spans.setdefault(
                (inv1.syscall_loc, inv2.syscall_loc),
                SpanInfo(),
            ).pairs.append((inv1, inv2))

    for thread in trace.threads.values():
        thread.calculate_userspace_times()

    return trace
