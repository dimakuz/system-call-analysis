import dataclasses
import logging
import os
import pathlib
import shlex
import subprocess
import tempfile
import time
import typing
import sys

import dacite
import pandas
from plotly import graph_objects
import yaml

from harness import analysis
from harness import podman
from harness import syscall_info

LOG = logging.getLogger(__name__)


@dataclasses.dataclass
class Container:
    image: str
    env: typing.Dict[str, str]
    setup_commands: typing.List[str]
    test_commands: typing.List[str]


@dataclasses.dataclass
class RunInfo:
    container: Container
    bpftrace_script: str


def discover_workload_uid(cont):
    res = podman.top(cont, 'huser')
    rows = iter(res.split('\n'))
    next(rows)
    return int(next(rows))


def get_bfptrace_output(run_info, path):
    with podman.running_container(
        'postgres',
        name='test-postgres',
        env={'POSTGRES_PASSWORD': 'password'},
    ) as cont:
        # FIXME check that container is ready
        time.sleep(3)
        for command in run_info.container.setup_commands:
            podman.execute(cont, shlex.split(command))
        uid = discover_workload_uid(cont)
        with subprocess.Popen(
            (
                'sudo',
                'bpftrace',
                '-o', path, run_info.bpftrace_script,
                str(uid)
            ),
            preexec_fn=os.setpgrp,
            stderr=subprocess.DEVNULL,
        ) as proc:
            for command in run_info.container.test_commands:
                LOG.debug('Running test command: %s', command)
                podman.execute(cont, shlex.split(command))

            # sudo processes require special measures, as sudo won't relay
            # signal if command was not started on a pty
            # FIXME later to avoid killing other tracers
            subprocess.run(('sudo', 'pkill', 'bpftrace'), check=True)
            proc.wait()


def build_trace(path):
    with open(path) as f:
        # skip first line:
        next(f)

        headers = next(f).strip().split(',')

        def _to_row(line):
            line = line.strip()
            return dict(zip(headers, (int(e, 16) for e in line.split(','))))

        return analysis.build_trace(_to_row(l) for l in f if l.strip())


_USER_Y = 1000


def generate_syscall_plot(invocations):
    x, y = [0], [_USER_Y]
    for invocation in invocations:
        # Downward edge:
        x.append(invocation.start_ns - 1)
        y.append(_USER_Y)
        x.append(invocation.start_ns)
        y.append(invocation.syscall.nr)

        # Upward edge:
        x.append(invocation.end_ns)
        y.append(invocation.syscall.nr)
        x.append(invocation.end_ns + 1)
        y.append(_USER_Y)

    df = pandas.DataFrame(
        {
            'time': x,
            'exec': y,
        }
    )
    fig = graph_objects.Figure(
        graph_objects.Scatter(x=df['time'], y=df['exec']),
    )
    fig.update_layout(
        yaxis={
            'tickmode': 'array',
            'tickvals': [_USER_Y] + list(syscall_info.syscall_map.keys()),
            'ticktext': [
                'userspace',
            ] + list(syscall_info.syscall_map.values()),
        }
    )
    fig.show()


def run(run_info):
    with tempfile.TemporaryDirectory(suffix='bfptrace-res') as tmpdir:
        output = pathlib.Path(tmpdir) / 'raw-output'
        get_bfptrace_output(run_info, output)
        trace = build_trace(output)
        tid, thread = max(
            trace.threads.items(),
            key=lambda kv: len(kv[1].invocations),
        )
        LOG.debug(
            f"{tid}, {len(thread.invocations)}, {thread.average_interval}",
        )

        generate_syscall_plot(thread.invocations)
        # print(thread.userspace_time_quantiles)


def main():
    with open(sys.argv[1]) as f:
        run_info = dacite.from_dict(RunInfo, yaml.safe_load(f))
    run(run_info)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
