import dataclasses
import re
import statistics
import typing

from harness import syscall_info

_SYSCALLS = {}


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


@dataclasses.dataclass
class ThreadTrace:
    invocations: typing.List[SyscallInvocation] = dataclasses.field(
        default_factory=list,
    )
    ustacks: typing.Dict[int, typing.Tuple[str]] = dataclasses.field(
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
        return dict(zip(headers, (int(e, 16) for e in line.split(','))))

    for row in f:
        if not row.strip():
            continue
        if row.startswith('===='):
            break

        row = _to_row(row)
        try:
            sc = Syscall.from_nr(row['sysnr'])
        except KeyError:
            continue
        sci = SyscallInvocation(
            syscall=sc,
            start_ns=row['tbegin'],
            duration_ns=row['dur'],
            ustack_id=row['ustack']
        )
        tid = row['tid']
        trace.threads.setdefault(tid, ThreadTrace()).invocations.append(sci)

    for tid, stack, stack_id in re.findall(
        r'@ustacks\[(\d+),([^\]]*)\]: (\d+)',
        f.read(),
        re.M
    ):
        tid = int(tid)
        stack = tuple(l.strip() for l in stack.split())
        stack_id = int(stack_id)
        trace.threads[tid].ustacks[stack_id] = stack

    for tid, thread in trace.threads.items():
        for inv in thread.invocations:
            inv.ustack = thread.ustacks[inv.ustack_id]

        for inv1, inv2 in zip(thread.invocations, thread.invocations[1:]):
            thread.userspace_spans.setdefault(
                (inv1.syscall_loc, inv2.syscall_loc),
                SpanInfo(),
            ).pairs.append((inv1, inv2))

    for thread in trace.threads.values():
        thread.calculate_userspace_times()

    return trace
