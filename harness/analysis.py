import dataclasses
import statistics
import typing

from harness import syscall_info

_SYSCALLS = {}


@dataclasses.dataclass
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
    userspace_before: int = -1
    userspace_after: int = -1

    @property
    def end_ns(self):
        return self.start_ns + self.duration_ns


@dataclasses.dataclass
class ThreadTrace:
    invocations: typing.List[SyscallInvocation] = dataclasses.field(
        default_factory=list,
    )

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


def build_trace(rows):
    trace = Trace()
    for row in rows:
        try:
            sc = Syscall.from_nr(row['sysnr'])
        except KeyError:
            continue
        sci = SyscallInvocation(
            syscall=sc,
            start_ns=row['tbegin'],
            duration_ns=row['dur'],
        )
        tid = row['tid']
        trace.threads.setdefault(tid, ThreadTrace()).invocations.append(sci)
    for thread in trace.threads.values():
        thread.calculate_userspace_times()
    return trace
