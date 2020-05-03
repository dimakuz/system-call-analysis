import dataclasses
import logging
import os
import typing

import graphviz


LOG = logging.getLogger(__name__)


@dataclasses.dataclass
class Call:
    func: 'Func'
    times: int


@dataclasses.dataclass(frozen=True)
class CallKey:
    off: int
    funckey: object


@dataclasses.dataclass
class Func:
    module: str
    name: str
    tag: str
    calls: typing.Dict[CallKey, Call] = dataclasses.field(
        default_factory=dict,
    )

    @property
    def key(self):
        return (self.module, self.name)

    @property
    def skey(self):
        return f'{self.tag}@@{self.name}@@{self.module}'

    @classmethod
    def from_frame(cls, frame):
        return cls(
            frame.module,
            frame.func,
            frame.tag,
        )

    def add_call(self, off, func):
        call = self.calls.setdefault(
           CallKey(off, func.key),
           Call(func, 0),
        )
        call.times += 1
        return call.func


@dataclasses.dataclass
class CallGraph:
    roots: typing.Dict[object, Func] = dataclasses.field(
        default_factory=dict,
    )
    funcs: typing.Dict[tuple, Func] = dataclasses.field(
        default_factory=dict,
    )

    def _get_root(self, frame):
        frame_func = Func.from_frame(frame)
        return self.roots.setdefault(frame_func.key, frame_func)

    def add_stack_trace(self, stack, times):
        rstack = tuple(reversed(stack))
        func = self._get_root(rstack[0])
        frame = rstack[0]
        for next_frame in rstack[1:]:
            next_func = func.add_call(
                frame.off,
                Func.from_frame(next_frame),
            )
            func = next_func
            frame = next_frame

    def _draw_tree(self, g, func):
        LOG.debug('Draw tree %r', func.key)
        if func.module == '[unknown]':
            cluster_name = func.name
        else:
            cluster_name = os.path.basename(func.module).replace('.', '-')
        with g.subgraph(name=f'cluster_{cluster_name}') as sg:
            sg.attr(color='black')
            sg.attr(label=cluster_name)
            sg.node(
                func.skey,
                label=f'{func.name}_{func.tag}',
            )
        for ck, call in func.calls.items():
            self._draw_tree(g, call.func)
            g.edge(
                func.skey,
                call.func.skey,
                label=f'@{ck.off} x{call.times}',
                constraint=(
                    call.func.module == 'postgres' and 'false' or 'true'
                ),
            )

    def to_dot(self):
        g = graphviz.Digraph(strict=True)
        g.attr(rankdir='TB')
        g.attr(Rank='sink')
        for root in self.roots.values():
            self._draw_tree(g, root)
        # for func in self.funcs.values():
        #     if func.module == '[unknown]':
        #         cluster_name = func.name
        #     else:
        #         cluster_name = os.path.basename(func.module).replace('.', '-')
        #     with g.subgraph(name=f'cluster_{cluster_name}') as sg:
        #         sg.attr(color='black')
        #         sg.attr(label=cluster_name)
        #         sg.node(
        #             func.skey,
        #             label=func.name,
        #         )
        # for func in self.funcs.values():
        #     for off, call in func.calls.items():
        #         # if func.module == callee.module:
        #         g.edge(
        #             func.skey,
        #             call.func.skey,
        #             label=f'@{off} x{call.times}',
        #             constraint=(
        #                 call.func.module == 'postgres' and 'false' or 'true'
        #             ),
        #         )
        # for func in self.funcs.values():
        #     for key, callee in func.calls.items():
        #         if func.module != callee.module:
        #             g.edge(
        #                 func.skey,
        #                 callee.skey,
        #                 label=str(key),
        #                 constraint=(
        #                     callee.name == 'main' and 'false' or 'true'
        #                 ),
        #             )
        return g
