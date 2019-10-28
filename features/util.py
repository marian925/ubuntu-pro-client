import subprocess
import time
from typing import Any, List

from behave.runner import Context


def lxc_exec(
    container_name: str, cmd: List[str], *args: Any, **kwargs: Any
) -> subprocess.CompletedProcess:
    """Run `lxc exec` in a container.

    :param container_name:
        The name of the container to run `lxc exec` against.
    :param cmd:
        A list containing the command to be run and its parameters; this will
        be appended to a list that is passed to `subprocess.run`.
    :param args, kwargs:
        These are passed directly to `subprocess.run`.

    :return:
        The `subprocess.CompletedProcess` returned by `subprocess.run`.
    """
    return subprocess.run(
        ["lxc", "exec", container_name, "--"] + cmd, *args, **kwargs
    )


def wait_for_boot(context: Context) -> None:
    """Wait for a test container to boot.

    :param context:
        A `behave.runner.Context` which should have `container_name` set on it.
        The container named `context.container_name` will be operated on.
    """
    retries = [2] * 5
    for sleep_time in retries:
        process = lxc_exec(
            context.container_name,
            ["runlevel"],
            capture_output=True,
            text=True,
        )
        try:
            _, runlevel = process.stdout.strip().split(" ", 2)
        except ValueError:
            print("Unexpected runlevel output: ", process.stdout.strip())
            runlevel = None
        if runlevel == "2":
            break
        time.sleep(sleep_time)
    else:
        raise Exception("System did not boot in {}s".format(sum(retries)))
