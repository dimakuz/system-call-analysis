import argparse
import dataclasses
import itertools
import json
import logging
import os
import pathlib
import shlex
import statistics
import subprocess
import tempfile
import time
import typing
import sys

import dacite
import graphviz
import pandas
from plotly import graph_objects
import yaml

from harness import analysis
from harness import graphanalysis
from harness import podman

LOG = logging.getLogger(__name__)


@dataclasses.dataclass
class Container:
    image: str
    test_commands: typing.List[str]
    command: typing.List[str] = dataclasses.field(
        default_factory=list,
    )
    extra_args: typing.List[str] = dataclasses.field(
        default_factory=list,
    )
    env: typing.Dict[str, str] = dataclasses.field(
        default_factory=dict,
    )
    setup_commands: typing.List[str] = dataclasses.field(
        default_factory=list,
    )
    post_commands: typing.List[str] = dataclasses.field(
        default_factory=list,
    )


@dataclasses.dataclass
class TracerInfo:
    bpftrace_script: str
    output_filename: str
    output_format: str


@dataclasses.dataclass
class RunInfo:
    container: Container
    tracers: typing.List[TracerInfo]


def discover_workload_uid(cont):
    res = podman.top(cont, 'huser')
    rows = iter(res.split('\n'))
    next(rows)
    return int(next(rows))


def get_bfptrace_output(run_info, output_dir):
    output_vol = (output_dir / 'vol').absolute()
    output_vol.mkdir(exist_ok=True)
    with podman.running_container(
        run_info.container.image,
        env=run_info.container.env,
        command=run_info.container.command,
        extra_args=(
            '-v', f'{output_vol}:/output:rw',
        ) + tuple(run_info.container.extra_args or ()),
    ) as cont:
        # FIXME check that container is ready
        time.sleep(3)
        for command in run_info.container.setup_commands:
            podman.execute(cont, shlex.split(command))
        # uid = discover_workload_uid(cont)

        # Start all tracers
        tracers = []
        for ti in run_info.tracers:
            cmd = (
                'sudo',
                '-E',
                'env',
                'LD_LIBRARY_PATH=/home/dimak/projects/thesis/syscallets/bcc/build/src/cc',
                'BPFTRACE_SHOW_USER_MODULE=1',
                '/home/dimak/projects/thesis/syscallets/ebpf/bpftrace/build/src/bpftrace',
                '--unsafe',
                '-f', ti.output_format,
                '-o', (output_dir / ti.output_filename).absolute(),
                pathlib.Path(ti.bpftrace_script).absolute(),
                # str(uid),
            )
            LOG.debug('Running %s', cmd)
            tracers.append(
                subprocess.Popen(
                    cmd,
                    preexec_fn=os.setpgrp,
                    env={
                        'BPFTRACE_CACHE_USER_SYMBOLS': '1',
                        'BPFTRACE_MAP_KEYS_MAX': '8192',
                        'LD_LIBRARY_PATH': '/home/dimak/projects/thesis/syscallets/bcc/build/src/cc',
                    },
                    # stderr=subprocess.DEVNULL,
                ),
            )
        for command in run_info.container.test_commands:
            LOG.debug('Running test command: %s', command)
            podman.execute(cont, shlex.split(command))

        # sudo processes require special measures, as sudo won't relay
        # signal if command was not started on a pty
        # FIXME later to avoid killing other tracers
        subprocess.run(('sudo', 'pkill', 'bpftrace'), check=True)
        for p in tracers:
            p.wait()

        for command in run_info.container.post_commands:
            LOG.debug('Running post command: %s', command)
            podman.execute(cont, shlex.split(command))


def build_trace(path):
    with open(path) as f:
        # skip first line:
        next(f)
        trace = analysis.build_trace(f)
    return trace


_USER_Y = 1000


def generate_syscall_plot(invocations):
    syscall_map = {}
    for invocation in invocations:
        if invocation.syscall.nr not in syscall_map:
            syscall_map[invocation.syscall.nr] = invocation.syscall.name
    syscall_remap = dict(
        zip(
            syscall_map.values(),
            itertools.count(
                10,
                900 // len(syscall_map),
            ),
        ),
    )

    x, y = [0], [_USER_Y]
    for invocation in invocations:
        # Downward edge:
        x.append(invocation.start_ns - 1)
        y.append(_USER_Y)
        x.append(invocation.start_ns)
        y.append(syscall_remap[invocation.syscall.name])

        # Upward edge:
        x.append(invocation.end_ns)
        y.append(syscall_remap[invocation.syscall.name])
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
            'tickvals': [_USER_Y] + list(syscall_remap.values()),
            'ticktext': [
                'userspace',
            ] + list(syscall_remap.keys()),
        },
        xaxis_tickformat='',
    )
    return fig


def run(run_info, plot_path):
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

        fig = generate_syscall_plot(thread.invocations)
        fig.write_html(plot_path)
        # print(thread.userspace_time_quantiles)


def produce_bpftrace_output(opts):
    with open(opts.spec) as f:
        run_info = dacite.from_dict(RunInfo, yaml.safe_load(f))
    os.makedirs(opts.output, exist_ok=True)
    get_bfptrace_output(run_info, opts.output)


def parse_stack(strval):
    return strval.strip().split()


def stacktree_add(st, ustack, syscall, count):
    for frame in ustack[::-1]:
        st = st.setdefault(frame, {})
    st[syscall] = count


def parse_ustacks(opts):
    st = {}
    with open(opts.input_path) as f:
        for l in f:
            o = json.loads(l)
            if o['type'] != 'map':
                continue
            for k, v in o['data'].items():
                syscall = k
                for k, v in v.items():
                    if v < 100:
                        continue
                    k = k.split(',')
                    ustack = parse_stack(k[1])
                    stacktree_add(st, ustack, syscall, v)
    dot = graphviz.Digraph()
    dot.attr(label='Stack graph')
    dot.attr(labelloc='top')
    dot.node()
    print(len(st))


@dataclasses.dataclass
class Node:
    value: typing.List[str]
    in_edges: typing.Set[str]
    out_edges: typing.Set[str]
    removed: int = 0

    @property
    def key(self):
        return min(self.value)

    @property
    def pretty_name(self):
        if len(self.value) == 1:
            return self.value[0]
        elif len(self.value) == 2:
            return f'{self.value[0]}\n{self.value[1]}'
        elif True:
            return '\n'.join(self.value)
        else:
            return (
                f'{self.value[0]}\n' +
                f'...({len(self.value) - 2})...\n' +
                f'{self.value[-1]}'
            )


def stack_graph(ustacks):
    nodes = {}
    for stack in ustacks:
        # print('->'.join(s[-5:] for s in stack))
        for frame in stack:
            nodes[frame] = Node([frame], set(), set())

    for stack in ustacks:
        for ftop, fbot in zip(stack, stack[1:]):
            nodes[ftop].in_edges.add(fbot)
            nodes[fbot].out_edges.add(ftop)
    while compress_one_edge(nodes):
        pass
    return nodes


def compress_one_edge(nodes):
    for head in nodes.values():
        # Try folding head into tail
        if len(head.in_edges) != 1:
            continue
        tail_id = next(iter(head.in_edges))
        tail = nodes[tail_id]

        if len(tail.out_edges) > 1:
            continue
        if tail.out_edges != {head.key}:
            raise RuntimeError()

        new_node = Node(
            tail.value + head.value,
            tail.in_edges,
            head.out_edges,
        )

        for v in head.out_edges:
            v = nodes[v]
            v.in_edges.discard(head.key)
            v.in_edges.add(new_node.key)

        for v in tail.in_edges:
            v = nodes[v]
            v.out_edges.discard(tail.key)
            v.out_edges.add(new_node.key)

        del nodes[head.key]
        del nodes[tail.key]
        head.removed = 1
        tail.removed = 1
        nodes[new_node.key] = new_node
        return True
    return False


def _stack_diff(s1, s2):
    s1 = s1[::-1]
    s2 = s2[::-1]
    comb = zip(s1, s2)
    fcomb = list(filter(lambda a: a[0] == a[1], comb))
    return len(s1) - len(fcomb),  len(s2) - len(fcomb)


def _inv_node(inv):
    return f'{inv.syscall.name}-{inv.ustack_id}'


def build_thread_graph(thread, draw_userspace=True, span_pred=None):
    dot = graphviz.Digraph(strict=True)
    draw_legend(dot)

    nr_spans = len(thread.userspace_spans)
    LOG.debug("Thread has %d spans", nr_spans)
    valid_spans = []
    ustacks = set()
    for info in thread.userspace_spans.values():
        if span_pred is not None and not span_pred(info):
            continue
        valid_spans.append(info)
        for inv in info.pairs[0]:
            ustacks.add(inv.ustack)
    if not valid_spans:
        return

    LOG.debug("Thread has [%d/%d] valid spans", len(valid_spans), nr_spans)

    nodes = stack_graph(ustacks)
    LOG.debug('Constructed stack graph of size %d', len(nodes))
    drawn_userspace = set()

    for i, info in enumerate(valid_spans):
        i1, i2 = info.pairs[0]

        LOG.debug(
            '[%d/%d] Processing span %r %r (%d)',
            i + 1, len(valid_spans),
            i1.syscall_loc, i2.syscall_loc, len(info.pairs),
        )

        for inv in (i1, i2):
            durations = tuple(
                i.duration_ns
                for i in thread.invocations
                if i.syscall_loc == inv.syscall_loc
            )
            mean = statistics.mean(durations)
            median = statistics.median(durations)
            label = (
                _inv_node(inv) + f' (x{len(durations)})\n' +
                f'[{mean / 1000:.2f}, {median / 1000:.2f}]'
            )
            dot.node(
                _inv_node(inv),
                fontcolor='red',
                label=label,
            )
            if draw_userspace:
                us_node = None
                LOG.debug('stack trace is %r', inv.ustack)
                for frame in inv.ustack[::-1]:
                    us_node = next(
                        n for n in nodes.values() if frame in n.value
                    )
                    dot.node(
                        us_node.pretty_name,
                    )
                    drawn_userspace.add(us_node.key)

                if us_node is not None:
                    LOG.debug(us_node.value)
                    LOG.debug('adding edge')
                    dot.edge(
                        us_node.pretty_name,
                        _inv_node(inv),
                    )
        mean, median = info.mean_median()
        label = (
            f'{len(info.pairs)}, {_stack_diff(i1.ustack, i2.ustack)}\n' +
            f'[{mean / 1000:.2f}, {median / 1000:.2f}]'
        )
        dot.edge(
            _inv_node(i1),
            _inv_node(i2),
            style='dashed',
            label=label,
        )

    # Fill in userspace edges
    if draw_userspace:
        for key in drawn_userspace:
            tail = nodes[key]
            for headkey in drawn_userspace.intersection(tail.out_edges):
                head = nodes[headkey]
                dot.edge(tail.pretty_name, head.pretty_name)

    return dot


def draw_legend(dot):
    # Draw legend
    dot.node(
        'l0',
        label='{{stack frame}}\naddr1'
    )
    dot.node(
        'l1',
        label=(
            '{{Syscall invocation}}\n'
            'syscall1-stack_ID\n'
            'Duration in us: [mean, median]'
        ),
        fontcolor='red',
    )
    dot.node(
        'l2',
        label=(
            '{{Another systcall invocation}}\n'
            'syscall2-stack_ID\n'
            'Duration in us: [mean, median]'
        ),
        fontcolor='red',
    )
    dot.edge(
        'l0',
        'l1',
        label='Invocation of syscall1\nby stack frame addr1',
    )
    dot.edge(
        'l1',
        'l2',
        style='dashed',
        label=(
            '{{syscall2 follows syscall1}}\n'
            'Number of recorded events (stack distance)\n'
            'Time between callls in us: [mean, median]'
        )
    )


def dump_dot(dot, path):
    subprocess.run(
        ('dot', '-Tpng', '-o', path),
        input=dot.source,
        encoding='utf8',
    )
    print(f'file://{path}')


def analyze_syscalls(opts):
    trace = build_trace(opts.input_path)
    LOG.debug('Trace built')
    for tid, thread in trace.threads.items():
        LOG.debug("%d: %d", tid, len(thread.invocations))
        # tid, thread = max(
        #     trace.threads.items(),
        #     key=lambda kv: len(kv[1].invocations),
        # )
        LOG.debug('Working on thread %d', tid)

        def span_pred(span_info):
            if len(span_info.pairs) < 1000:
                return False
            # More than 50us apart?
            _, median = span_info.mean_median()
            if median > 50000:
                return False
            return True

        dot = build_thread_graph(
            thread,
            draw_userspace=opts.draw_userspace,
            span_pred=span_pred,
        )
        if not dot:
            continue
        LOG.debug('Graph constructed, dumping it')

        dump_dot(dot, f'/tmp/res.{tid}.png')
        # for k, v in sorted(thread.userspace_spans.items()):
        #     if not span_pred(v):
        #         continue
        #     quantiles = v.quantiles()
        #     print(tuple(_inv_node(i) for i in v.pairs[0]))
        #     print(quantiles)
        #     print(v.pairs[0][0])
        #     print(v.pairs[0][1])
        #     print('')


def build_call_graph(opts):
    trace = build_trace(opts.input_path)
    cg = graphanalysis.CallGraph()
    LOG.debug('Trace built')
    tid, thread = max(
        trace.threads.items(),
        key=lambda kv: len(kv[1].invocations),
    )
    # for tid, thread in trace.threads.items():
    for inv in thread.invocations:
        cg.add_stack_trace(inv.ustack2, 1)
    dump_dot(cg.to_dot(), f'/tmp/rescg.png')


@dataclasses.dataclass
class _SAResult:
    frm: int
    to: int
    ratio: float
    syscalls: int

def span_analysis(opts):
    trace = build_trace(opts.input_path)
    LOG.debug('Trace built')
    tid, thread = max(
        trace.threads.items(),
        key=lambda kv: len(kv[1].invocations),
    )
    for i in range(len(thread.invocations)):
        LOG.debug(f'[{i+1}/{len(thread.invocations)}]')
        for j in range(i + 1, min(i + 100, len(thread.invocations))):
            invs = thread.invocations[i:j]
            r = _SAResult(
                i,
                j,
                (
                    sum(i.duration_ns for i in invs)
                    /
                    (invs[-1].end_ns + invs[-1].userspace_after - invs[0].start_ns)
                ),
                j-i,
            )
            print(r)


def main():
    parser = argparse.ArgumentParser(sys.argv[0])
    subparsers = parser.add_subparsers()
    parser_trace = subparsers.add_parser('trace-container')
    parser_trace.add_argument('spec', help='YAML containing env description')
    parser_trace.add_argument(
        'output',
        help='output directory',
        type=pathlib.Path,
    )
    parser_trace.set_defaults(func=produce_bpftrace_output)

    parser_ustacks = subparsers.add_parser('parse-ustacks')
    parser_ustacks.add_argument('input_path', type=pathlib.Path)
    parser_ustacks.set_defaults(func=parse_ustacks)

    parser_syscalls = subparsers.add_parser('analyze-syscalls')
    parser_syscalls.add_argument('input_path', type=pathlib.Path)
    parser_syscalls.add_argument(
        '--draw-userspace',
        action='store_true',
        dest='draw_userspace',
        default=False,
    )
    parser_syscalls.set_defaults(func=analyze_syscalls)

    parser_syscalls = subparsers.add_parser('build-call-graph')
    parser_syscalls.add_argument('input_path', type=pathlib.Path)
    parser_syscalls.set_defaults(func=build_call_graph)

    parser_syscalls = subparsers.add_parser('span-analysis')
    parser_syscalls.add_argument('input_path', type=pathlib.Path)
    parser_syscalls.set_defaults(func=span_analysis)

    logging.basicConfig(level=logging.DEBUG)
    opts = parser.parse_args()
    opts.func(opts)


if __name__ == '__main__':
    main()
