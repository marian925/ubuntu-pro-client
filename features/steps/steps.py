import datetime
import shlex
import subprocess

from behave import given, then, when
from hamcrest import assert_that, equal_to

from features.util import lxc_exec, wait_for_boot


CONTAINER_PREFIX = "behave-test-"


@given("a trusty lxd container")
def given_a_trusty_lxd_container(context):
    now = datetime.datetime.now()
    context.container_name = CONTAINER_PREFIX + now.strftime("%s%f")
    subprocess.run(["lxc", "launch", "ubuntu:trusty", context.container_name])

    def cleanup_container():
        subprocess.run(["lxc", "stop", context.container_name])
        subprocess.run(["lxc", "delete", context.container_name])

    context.add_cleanup(cleanup_container)

    wait_for_boot(context)


@given("ubuntu-advantage-tools is installed")
def given_uat_is_installed(context):
    lxc_exec(
        context.container_name,
        [
            "add-apt-repository",
            "--yes",
            "ppa:canonical-server/ua-client-daily",
        ],
    )
    lxc_exec(context.container_name, ["apt-get", "update", "-qq"])
    lxc_exec(
        context.container_name,
        ["apt-get", "install", "-qq", "-y", "ubuntu-advantage-tools"],
    )


@when("I run `{command}` as {user}")
def when_i_run_command(context, command, user):
    prefix = []
    if user == "root":
        prefix = ["sudo"]
    elif user != "non-root":
        raise Exception(
            "The two acceptable values for user are: root, non-root"
        )
    process = lxc_exec(
        context.container_name,
        prefix + shlex.split(command),
        capture_output=True,
        text=True,
    )
    context.process = process


@then("I will see the following on stdout")
def then_i_will_see_on_stdout(context):
    assert_that(context.process.stdout.strip(), equal_to(context.text))


@then("I will see the following on stderr")
def then_i_will_see_on_stderr(context):
    assert_that(context.process.stderr.strip(), equal_to(context.text))
