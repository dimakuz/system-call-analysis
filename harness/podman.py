'''Wrapper for command-line invocation of podman

See podman man-pages for specifics on each of the verbs.
'''

import contextlib
import logging
import subprocess


LOG = logging.getLogger(__name__)


def _podman(*args, check=True):
    command = tuple(
        str(s)
        for s in ('sudo', 'podman',) + tuple(args)
    )
    LOG.debug('Running command: %s', ' '.join(command))
    res = subprocess.run(
        command,
        capture_output=True,
        encoding='utf8',
        check=check,
    )
    LOG.debug("Result %r", res)
    return res.stdout


@contextlib.contextmanager
def running_container(image, **kwargs):
    name = create(image, **kwargs)
    try:
        yield name
    finally:
        remove(name)


def create(image, command=(), name=(), env=None, extra_args=()):
    if name:
        name = ('--name', name)
    if env is None:
        env_args = ()
    else:
        env_args = []
        for k, v in env.items():
            env_args.extend(('-e', f'{k}={v}'))

    res = _podman(
        'run',
        '--detach',
        *extra_args,
        *env_args,
        *name,
        image,
        *command,
    )
    return res.strip()


def remove(name):
    _podman('rm', '-f', name)


def remove_image(name):
    _podman('rmi', name)


def execute(name, command, check=True):
    return _podman('exec', name, *command, check=check)


def copy_in(name, host_path, container_path):
    _podman(
        'cp',
        '--pause=false',
        host_path,
        f'{name}:{container_path}',
    )


def top(name, *fields):
    return _podman(
        'top',
        name,
        '-eo',
        *fields,
    )
