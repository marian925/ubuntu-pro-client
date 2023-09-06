import re
import textwrap
from typing import Dict, List, NamedTuple, Optional, Set, Tuple, Union  # noqa

from uaclient import apt, exceptions, messages, security, system, util
from uaclient.api.u.pro.attach.magic.initiate.v1 import _initiate
from uaclient.api.u.pro.attach.magic.revoke.v1 import (
    MagicAttachRevokeOptions,
    _revoke,
)
from uaclient.api.u.pro.attach.magic.wait.v1 import (
    MagicAttachWaitOptions,
    _wait,
)
from uaclient.api.u.pro.security.fix import (  # noqa
    FixPlanAptUpgradeStep,
    FixPlanAttachStep,
    FixPlanEnableStep,
    FixPlanNoOpAlreadyFixedStep,
    FixPlanNoOpLivepatchFixStep,
    FixPlanNoOpStatus,
    FixPlanNoOpStep,
    FixPlanResult,
    FixPlanStep,
    FixPlanUSNResult,
    FixPlanWarning,
    FixPlanWarningPackageCannotBeInstalled,
    FixPlanWarningSecurityIssueNotFixed,
    NoOpAlreadyFixedData,
    NoOpLivepatchFixData,
    USNAdditionalData,
)
from uaclient.api.u.pro.security.fix.cve.plan.v1 import CVEFixPlanOptions
from uaclient.api.u.pro.security.fix.cve.plan.v1 import _plan as cve_plan
from uaclient.api.u.pro.security.fix.usn.plan.v1 import USNFixPlanOptions
from uaclient.api.u.pro.security.fix.usn.plan.v1 import _plan as usn_plan
from uaclient.api.u.pro.status.is_attached.v1 import _is_attached
from uaclient.cli.constants import NAME, USAGE_TMPL
from uaclient.clouds.identity import (
    CLOUD_TYPE_TO_TITLE,
    PRO_CLOUD_URLS,
    get_cloud_type,
)
from uaclient.config import UAConfig
from uaclient.contract import ContractExpiryStatus, get_contract_expiry_status
from uaclient.defaults import PRINT_WRAP_WIDTH
from uaclient.entitlements import entitlement_factory
from uaclient.entitlements.entitlement_status import (
    ApplicabilityStatus,
    UserFacingStatus,
)
from uaclient.files import notices
from uaclient.files.notices import Notice
from uaclient.messages.urls import PRO_HOME_PAGE
from uaclient.security import FixStatus
from uaclient.status import colorize_commands


def set_fix_parser(subparsers):
    parser_fix = subparsers.add_parser(
        "fix",
        help="check for and mitigate the impact of a CVE/USN on this system",
    )
    parser_fix.set_defaults(action=action_fix)
    fix_parser(parser_fix)


def fix_parser(parser):
    """Build or extend an arg parser for fix subcommand."""
    parser.usage = USAGE_TMPL.format(
        name=NAME, command="fix <CVE-yyyy-nnnn+>|<USN-nnnn-d+>"
    )
    parser.prog = "fix"
    parser.description = (
        "Inspect and resolve CVEs and USNs (Ubuntu Security Notices) on this"
        " machine."
    )
    parser._optionals.title = "Flags"
    parser.add_argument(
        "security_issue",
        help=(
            "Security vulnerability ID to inspect and resolve on this system."
            " Format: CVE-yyyy-nnnn, CVE-yyyy-nnnnnnn or USN-nnnn-dd"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "If used, fix will not actually run but will display"
            " everything that will happen on the machine during the"
            " command."
        ),
    )
    parser.add_argument(
        "--no-related",
        action="store_true",
        help=(
            "If used, when fixing a USN, the command will not try to"
            " also fix related USNs to the target USN."
        ),
    )

    return parser


def print_cve_header(cve: FixPlanResult):
    lines = [
        "{issue}: {description}".format(
            issue=cve.title.upper(), description=cve.description
        ),
        " - https://ubuntu.com/security/{}".format(cve.title.upper()),
    ]

    print("\n".join(lines))


def print_usn_header(fix_plan: FixPlanUSNResult):
    target_usn = fix_plan.target_usn_plan
    lines = [
        "{issue}: {description}".format(
            issue=target_usn.title.upper(), description=target_usn.description
        ),
    ]

    additional_data = target_usn.additional_data
    if isinstance(additional_data, USNAdditionalData):
        if additional_data.associated_cves:
            lines.append("Found CVEs:")
            for cve in additional_data.associated_cves:
                lines.append(" - https://ubuntu.com/security/{}".format(cve))
        elif additional_data.associated_launchpad_bugs:
            lines.append("Found Launchpad bugs:")
            for lp_bug in additional_data.associated_launchpad_bugs:
                lines.append(" - " + lp_bug)

    print("\n".join(lines))


def fix_cve(security_issue: str, dry_run: bool, cfg: UAConfig):
    fix_plan = cve_plan(
        options=CVEFixPlanOptions(cves=[security_issue]), cfg=cfg
    )

    error = fix_plan.cves_data.cves[0].error
    if error:
        raise exceptions.UserFacingError(error.msg)
    print_cve_header(fix_plan.cves_data.cves[0])
    print()

    status, _ = execute_fix_plan(fix_plan.cves_data.cves[0], dry_run, cfg)
    return status


def fix_usn(
    security_issue: str, dry_run: bool, no_related: bool, cfg: UAConfig
):
    fix_plan = usn_plan(
        options=USNFixPlanOptions(usns=[security_issue]), cfg=cfg
    )
    error = fix_plan.usns_data.usns[0].target_usn_plan.error
    if error:
        raise exceptions.UserFacingError(error.msg)
    print_usn_header(fix_plan.usns_data.usns[0])

    print(
        "\n"
        + messages.SECURITY_FIXING_REQUESTED_USN.format(
            issue_id=security_issue
        )
    )

    target_usn_status, _ = execute_fix_plan(
        fix_plan.usns_data.usns[0].target_usn_plan,
        dry_run,
        cfg,
    )

    if target_usn_status not in (
        FixStatus.SYSTEM_NON_VULNERABLE,
        FixStatus.SYSTEM_NOT_AFFECTED,
    ):
        return target_usn_status

    related_usns_plan = fix_plan.usns_data.usns[0].related_usns_plan
    if not related_usns_plan or no_related:
        return target_usn_status

    print(
        "\n"
        + messages.SECURITY_RELATED_USNS.format(
            related_usns="\n- ".join(usn.title for usn in related_usns_plan)
        )
    )

    print("\n" + messages.SECURITY_FIXING_RELATED_USNS)
    related_usn_status = (
        {}
    )  # type: Dict[str, Tuple[FixStatus, List[security.UnfixedPackage]]]
    for related_usn_plan in related_usns_plan:
        print("- {}".format(related_usn_plan.title))
        related_usn_status[related_usn_plan.title] = execute_fix_plan(
            related_usn_plan,
            dry_run,
            cfg,
        )
        print()

    print(messages.SECURITY_USN_SUMMARY)
    _handle_fix_status_message(
        target_usn_status, security_issue, extra_info=" [requested]"
    )

    failure_on_related_usn = False
    for related_usn_plan in related_usns_plan:
        status, unfixed_pkgs = related_usn_status[related_usn_plan.title]
        _handle_fix_status_message(
            status, related_usn_plan.title, extra_info=" [related]"
        )

        if status == FixStatus.SYSTEM_VULNERABLE_UNTIL_REBOOT:
            print(
                "- "
                + messages.ENABLE_REBOOT_REQUIRED_TMPL.format(
                    operation="fix operation"
                )
            )
            failure_on_related_usn = True
        if status == FixStatus.SYSTEM_STILL_VULNERABLE:
            for unfixed_pkg in unfixed_pkgs:
                if unfixed_pkg.unfixed_reason:
                    print(
                        "  - {}: {}".format(
                            unfixed_pkg.pkg, unfixed_pkg.unfixed_reason
                        )
                    )
            failure_on_related_usn = True

    if failure_on_related_usn:
        print(
            "\n"
            + messages.SECURITY_RELATED_USN_ERROR.format(
                issue_id=security_issue
            )
        )

    return target_usn_status


def status_message(status, pocket_source: Optional[str] = None):
    if status == "needed":
        return messages.SECURITY_CVE_STATUS_NEEDED
    elif status == "needs-triage":
        return messages.SECURITY_CVE_STATUS_TRIAGE
    elif status == "pending":
        return messages.SECURITY_CVE_STATUS_PENDING
    elif status in ("ignored", "deferred"):
        return messages.SECURITY_CVE_STATUS_IGNORED
    elif status == "DNE":
        return messages.SECURITY_CVE_STATUS_DNE
    elif status == "not-affected":
        return messages.SECURITY_CVE_STATUS_NOT_AFFECTED
    elif status == "released" and pocket_source:
        return messages.SECURITY_FIX_RELEASE_STREAM.format(
            fix_stream=pocket_source
        )
    return messages.SECURITY_CVE_STATUS_UNKNOWN.format(status=status)


def _format_packages_message(
    pkg_list: List[str],
    status: str,
    pkg_index: int,
    num_pkgs: int,
    pocket_source: Optional[str] = None,
) -> str:
    """Format the packages and status to an user friendly message."""
    if not pkg_list:
        return ""

    msg_index = []
    src_pkgs = []
    for src_pkg in pkg_list:
        pkg_index += 1
        msg_index.append("{}/{}".format(pkg_index, num_pkgs))
        src_pkgs.append(src_pkg)

    msg_header = textwrap.fill(
        "{} {}:".format(
            "(" + ", ".join(msg_index) + ")", ", ".join(sorted(src_pkgs))
        ),
        width=PRINT_WRAP_WIDTH,
        subsequent_indent="    ",
    )
    return "{}\n{}".format(msg_header, status_message(status, pocket_source))


def _run_ua_attach(cfg: UAConfig, token: str) -> bool:
    """Attach to an Ubuntu Pro subscription with a given token.

    :return: True if attach performed without errors.
    """
    import argparse

    from uaclient import cli

    print(colorize_commands([["pro", "attach", token]]))
    try:
        ret_code = cli.action_attach(
            argparse.Namespace(
                token=token, auto_enable=True, format="cli", attach_config=None
            ),
            cfg,
        )
        return ret_code == 0
    except exceptions.UserFacingError as err:
        print(err.msg)
        return False


def _inform_ubuntu_pro_existence_if_applicable() -> None:
    """Alert the user when running Pro on cloud with PRO support."""
    cloud_type, _ = get_cloud_type()
    if cloud_type in PRO_CLOUD_URLS.keys():
        print(
            messages.SECURITY_USE_PRO_TMPL.format(
                title=CLOUD_TYPE_TO_TITLE.get(cloud_type), cloud=cloud_type
            )
        )


def _perform_magic_attach(cfg: UAConfig):
    print(messages.CLI_MAGIC_ATTACH_INIT)
    initiate_resp = _initiate(cfg=cfg)
    print(
        "\n"
        + messages.CLI_MAGIC_ATTACH_SIGN_IN.format(
            user_code=initiate_resp.user_code
        )
    )

    wait_options = MagicAttachWaitOptions(magic_token=initiate_resp.token)

    try:
        wait_resp = _wait(options=wait_options, cfg=cfg)
    except exceptions.MagicAttachTokenError as e:
        print(messages.CLI_MAGIC_ATTACH_FAILED)

        revoke_options = MagicAttachRevokeOptions(
            magic_token=initiate_resp.token
        )
        _revoke(options=revoke_options, cfg=cfg)
        raise e

    print("\n" + messages.CLI_MAGIC_ATTACH_PROCESSING)
    return _run_ua_attach(cfg, wait_resp.contract_token)


def _prompt_for_attach(cfg: UAConfig) -> bool:
    """Prompt for attach to a subscription or token.

    :return: True if attach performed.
    """
    _inform_ubuntu_pro_existence_if_applicable()
    print(messages.SECURITY_UPDATE_NOT_INSTALLED_SUBSCRIPTION)
    choice = util.prompt_choices(
        messages.SECURITY_FIX_ATTACH_PROMPT,
        valid_choices=["s", "a", "c"],
    )
    if choice == "c":
        return False
    if choice == "s":
        return _perform_magic_attach(cfg)
    if choice == "a":
        print(messages.PROMPT_ENTER_TOKEN)
        token = input("> ")
        return _run_ua_attach(cfg, token)

    return True


def _format_unfixed_packages_msg(unfixed_pkgs: List[str]) -> str:
    """Format the list of unfixed packages into an message.

    :returns: A string containing the message output for the unfixed
              packages.
    """
    num_pkgs_unfixed = len(unfixed_pkgs)
    return textwrap.fill(
        messages.SECURITY_PKG_STILL_AFFECTED.format(
            num_pkgs=num_pkgs_unfixed,
            s="s" if num_pkgs_unfixed > 1 else "",
            verb="are" if num_pkgs_unfixed > 1 else "is",
            pkgs=", ".join(sorted(unfixed_pkgs)),
        ).msg,
        width=PRINT_WRAP_WIDTH,
        subsequent_indent="    ",
    )


def _check_subscription_is_expired(cfg: UAConfig, dry_run: bool) -> bool:
    """Check if the Ubuntu Pro subscription is expired.

    :returns: True if subscription is expired and not renewed.
    """
    contract_expiry_status = get_contract_expiry_status(cfg)
    if contract_expiry_status[0] == ContractExpiryStatus.EXPIRED:
        if dry_run:
            print(messages.SECURITY_DRY_RUN_UA_EXPIRED_SUBSCRIPTION)
            return False
        return True

    return False


def _prompt_for_new_token(cfg: UAConfig) -> bool:
    """Prompt for attach a new subscription token to the user.

    :return: True if attach performed.
    """
    import argparse

    from uaclient import cli

    _inform_ubuntu_pro_existence_if_applicable()
    print(messages.SECURITY_UPDATE_NOT_INSTALLED_EXPIRED)
    choice = util.prompt_choices(
        "Choose: [R]enew your subscription (at {}) [C]ancel".format(
            PRO_HOME_PAGE
        ),
        valid_choices=["r", "c"],
    )
    if choice == "r":
        print(messages.PROMPT_EXPIRED_ENTER_TOKEN)
        token = input("> ")
        print(colorize_commands([["pro", "detach"]]))
        cli.action_detach(
            argparse.Namespace(assume_yes=True, format="cli"), cfg
        )
        return _run_ua_attach(cfg, token)

    return False


def _prompt_for_enable(cfg: UAConfig, service: str) -> bool:
    """Prompt for enable a pro service.

    :return: True if enable performed.
    """
    import argparse

    from uaclient import cli

    print(messages.SECURITY_SERVICE_DISABLED.format(service=service))
    choice = util.prompt_choices(
        "Choose: [E]nable {} [C]ancel".format(service),
        valid_choices=["e", "c"],
    )

    if choice == "e":
        print(colorize_commands([["pro", "enable", service]]))
        return bool(
            0
            == cli.action_enable(
                argparse.Namespace(
                    service=[service],
                    assume_yes=True,
                    beta=False,
                    format="cli",
                    access_only=False,
                ),
                cfg,
            )
        )

    return False


def _handle_subscription_for_required_service(
    service: str, cfg: UAConfig, dry_run: bool
) -> bool:
    """
    Verify if the Ubuntu Pro subscription has the required service enabled.
    """
    ent_cls = entitlement_factory(cfg=cfg, name=service)
    ent = ent_cls(cfg)
    if ent:
        ent_status, _ = ent.user_facing_status()

        if ent_status == UserFacingStatus.ACTIVE:
            return True

        applicability_status, _ = ent.applicability_status()
        if applicability_status == ApplicabilityStatus.APPLICABLE:
            if dry_run:
                print(
                    "\n"
                    + messages.SECURITY_DRY_RUN_UA_SERVICE_NOT_ENABLED.format(
                        service=ent.name
                    )
                )
                return True

            if _prompt_for_enable(cfg, ent.name):
                return True
            else:
                print(
                    messages.SECURITY_UA_SERVICE_NOT_ENABLED.format(
                        service=ent.name
                    )
                )

        else:
            print(
                messages.SECURITY_UA_SERVICE_NOT_ENTITLED.format(
                    service=ent.name
                )
            )

    return False


def _handle_fix_status_message(
    status: FixStatus, issue_id: str, extra_info: str = ""
):
    if status == FixStatus.SYSTEM_NON_VULNERABLE:
        print(
            util.handle_unicode_characters(
                messages.SECURITY_ISSUE_RESOLVED.format(
                    issue=issue_id, extra_info=extra_info
                )
            )
        )
    elif status == FixStatus.SYSTEM_NOT_AFFECTED:
        print(
            util.handle_unicode_characters(
                messages.SECURITY_ISSUE_UNAFFECTED.format(
                    issue=issue_id, extra_info=extra_info
                )
            )
        )
    elif status == FixStatus.SYSTEM_VULNERABLE_UNTIL_REBOOT:
        print(
            util.handle_unicode_characters(
                messages.SECURITY_ISSUE_NOT_RESOLVED.format(
                    issue=issue_id, extra_info=extra_info
                )
            )
        )
    else:
        print(
            util.handle_unicode_characters(
                messages.SECURITY_ISSUE_NOT_RESOLVED.format(
                    issue=issue_id, extra_info=extra_info
                )
            )
        )


def execute_fix_plan(
    fix_plan: FixPlanResult, dry_run: bool, cfg: UAConfig
) -> Tuple[FixStatus, List[security.UnfixedPackage]]:
    full_plan = [
        *fix_plan.plan,
        *fix_plan.warnings,
    ]  # type: List[Union[FixPlanStep, FixPlanWarning]]

    pkg_index = 0
    unfixed_pkgs = []  # type: List[security.UnfixedPackage]
    installed_pkgs = set()  # type: Set[str]
    fix_status = FixStatus.SYSTEM_NON_VULNERABLE
    affected_pkgs = fix_plan.affected_packages or []
    print_pkg_header = True
    warn_package_cannot_be_installed = False

    if affected_pkgs:
        if len(affected_pkgs) == 1:
            plural_str = " is"
        else:
            plural_str = "s are"

        msg = (
            messages.SECURITY_AFFECTED_PKGS.format(
                count=len(affected_pkgs), plural_str=plural_str
            )
            + ": "
            + ", ".join(sorted(affected_pkgs))
        )
        print(
            textwrap.fill(
                msg,
                width=PRINT_WRAP_WIDTH,
                subsequent_indent="    ",
                replace_whitespace=False,
            )
        )

    for step in sorted(full_plan, key=lambda x: x.order):
        if isinstance(step, FixPlanWarningPackageCannotBeInstalled):
            if print_pkg_header:
                print(
                    _format_packages_message(
                        pkg_list=step.data.related_source_packages,
                        status="released",
                        pkg_index=pkg_index,
                        num_pkgs=len(affected_pkgs),
                        pocket_source=step.data.pocket,
                    )
                )
                print_pkg_header = False

            warn_msg = messages.FIX_CANNOT_INSTALL_PACKAGE.format(
                package=step.data.binary_package,
                version=step.data.binary_package_version,
            )
            print("- " + warn_msg.msg)
            unfixed_pkgs.append(
                security.UnfixedPackage(
                    pkg=step.data.source_package, unfixed_reason=warn_msg.msg
                )
            )
            fix_status = FixStatus.SYSTEM_STILL_VULNERABLE
            warn_package_cannot_be_installed = True
        if isinstance(step, FixPlanWarningSecurityIssueNotFixed):
            print(
                _format_packages_message(
                    pkg_list=step.data.source_packages,
                    status=step.data.status,
                    pkg_index=pkg_index,
                    num_pkgs=len(affected_pkgs),
                )
            )

            pkg_index += len(step.data.source_packages)
            for source_pkg in step.data.source_packages:
                unfixed_pkgs.append(
                    security.UnfixedPackage(
                        pkg=source_pkg,
                        unfixed_reason=status_message(step.data.status),
                    )
                )
            fix_status = FixStatus.SYSTEM_STILL_VULNERABLE
        if isinstance(step, FixPlanAptUpgradeStep):
            if print_pkg_header:
                print(
                    _format_packages_message(
                        pkg_list=step.data.source_packages,
                        status="released",
                        pkg_index=pkg_index,
                        num_pkgs=len(affected_pkgs),
                        pocket_source=step.data.pocket,
                    )
                )

            pkg_index += len(step.data.source_packages)
            if not step.data.binary_packages:
                if not warn_package_cannot_be_installed:
                    print(messages.SECURITY_UPDATE_INSTALLED)
                continue

            if not util.we_are_currently_root() and not dry_run:
                print(messages.SECURITY_APT_NON_ROOT)
                fix_status = FixStatus.SYSTEM_STILL_VULNERABLE
                for source_pkg in step.data.source_packages:
                    unfixed_pkgs.append(
                        security.UnfixedPackage(
                            pkg=source_pkg,
                            unfixed_reason=messages.SECURITY_APT_NON_ROOT,
                        )
                    )
                continue

            print(
                colorize_commands(
                    [
                        ["apt", "update", "&&"]
                        + ["apt", "install", "--only-upgrade", "-y"]
                        + sorted(step.data.binary_packages)
                    ]
                )
            )

            if dry_run:
                print_pkg_header = True
                continue

            try:
                apt.run_apt_update_command()
                apt.run_apt_command(
                    cmd=["apt-get", "install", "--only-upgrade", "-y"]
                    + step.data.binary_packages,
                    override_env_vars={"DEBIAN_FRONTEND": "noninteractive"},
                )
                installed_pkgs.update(step.data.binary_packages)
                print_pkg_header = True
            except Exception as e:
                print(getattr(e, "msg", str(e)))
                fix_status = FixStatus.SYSTEM_STILL_VULNERABLE

        if isinstance(step, FixPlanAttachStep):
            pocket = (
                security.UA_INFRA_POCKET
                if step.data.required_service == "esm-infra"
                else security.UA_APPS_POCKET
            )
            if print_pkg_header:
                print(
                    _format_packages_message(
                        pkg_list=step.data.source_packages,
                        status="released",
                        pkg_index=pkg_index,
                        num_pkgs=len(affected_pkgs),
                        pocket_source=pocket,
                    )
                )
                print_pkg_header = False

            if not _is_attached(cfg).is_attached:
                if dry_run:
                    print("\n" + messages.SECURITY_DRY_RUN_UA_NOT_ATTACHED)
                else:
                    if not _prompt_for_attach(cfg):
                        for source_pkg in step.data.source_packages:
                            unfixed_pkgs.append(
                                security.UnfixedPackage(
                                    pkg=source_pkg,
                                    unfixed_reason=messages.SECURITY_UA_SERVICE_REQUIRED.format(  # noqa
                                        service=step.data.required_service,
                                    ),
                                )
                            )
                        fix_status = FixStatus.SYSTEM_STILL_VULNERABLE
                        break
            elif _check_subscription_is_expired(cfg=cfg, dry_run=dry_run):
                if dry_run:
                    print(messages.SECURITY_DRY_RUN_UA_EXPIRED_SUBSCRIPTION)
                elif not _prompt_for_new_token(cfg):
                    for source_pkg in step.data.source_packages:
                        unfixed_pkgs.append(
                            security.UnfixedPackage(
                                pkg=source_pkg,
                                unfixed_reason=messages.SECURITY_UA_SERVICE_WITH_EXPIRED_SUB.format(  # noqa
                                    service=step.data.required_service,
                                ),
                            )
                        )
                    fix_status = FixStatus.SYSTEM_STILL_VULNERABLE
                    break

        if isinstance(step, FixPlanEnableStep):
            pocket = (
                security.UA_INFRA_POCKET
                if step.data.service == "esm-infra"
                else security.UA_APPS_POCKET
            )
            if print_pkg_header:
                print(
                    _format_packages_message(
                        pkg_list=step.data.source_packages,
                        status="released",
                        pkg_index=pkg_index,
                        num_pkgs=len(affected_pkgs),
                        pocket_source=pocket,
                    )
                )
                print_pkg_header = False

            if not _handle_subscription_for_required_service(  # noqa
                step.data.service,
                cfg,
                dry_run,
            ):
                print(
                    messages.SECURITY_UA_SERVICE_NOT_ENABLED.format(
                        service=step.data.service
                    )
                )
                for source_pkg in step.data.source_packages:
                    unfixed_pkgs.append(
                        security.UnfixedPackage(
                            pkg=source_pkg,
                            unfixed_reason=messages.SECURITY_UA_SERVICE_NOT_ENABLED_SHORT.format(  # noqa
                                service=step.data.service
                            ),
                        )
                    )
                fix_status = FixStatus.SYSTEM_STILL_VULNERABLE
                break

        if isinstance(step, FixPlanNoOpStep):
            if step.data.status == FixPlanNoOpStatus.NOT_AFFECTED.value:
                print(
                    messages.SECURITY_AFFECTED_PKGS.format(
                        count="No", plural_str="s are"
                    )
                    + "."
                )
                fix_status = FixStatus.SYSTEM_NOT_AFFECTED
        if isinstance(step, FixPlanNoOpLivepatchFixStep):
            if isinstance(step.data, NoOpLivepatchFixData):
                print(
                    messages.CVE_FIXED_BY_LIVEPATCH.format(
                        issue=fix_plan.title,
                        version=step.data.patch_version,
                    )
                )

        if isinstance(step, FixPlanNoOpAlreadyFixedStep):
            if isinstance(step.data, NoOpAlreadyFixedData):
                print(
                    _format_packages_message(
                        pkg_list=step.data.source_packages,
                        status="released",
                        pkg_index=pkg_index,
                        num_pkgs=len(affected_pkgs),
                        pocket_source=step.data.pocket,
                    )
                )
                print(messages.SECURITY_UPDATE_INSTALLED)
                pkg_index += len(step.data.source_packages)

    print()
    if unfixed_pkgs:
        print(
            _format_unfixed_packages_msg(
                list(set([unfixed_pkg.pkg for unfixed_pkg in unfixed_pkgs]))
            )
        )
        fix_status = FixStatus.SYSTEM_STILL_VULNERABLE

    if fix_status == FixStatus.SYSTEM_NON_VULNERABLE and system.should_reboot(
        installed_pkgs=installed_pkgs
    ):
        fix_status = FixStatus.SYSTEM_VULNERABLE_UNTIL_REBOOT
        reboot_msg = messages.ENABLE_REBOOT_REQUIRED_TMPL.format(
            operation="fix operation"
        )
        print(reboot_msg)
        notices.add(
            Notice.ENABLE_REBOOT_REQUIRED,
            operation="fix operation",
        )

    _handle_fix_status_message(fix_status, fix_plan.title)
    return (fix_status, unfixed_pkgs)


def action_fix(args, *, cfg, **kwargs):
    if not re.match(security.CVE_OR_USN_REGEX, args.security_issue):
        raise exceptions.InvalidSecurityIssueIdFormat(
            issue=args.security_issue
        )

    if args.dry_run:
        print(messages.SECURITY_DRY_RUN_WARNING)

    if "cve" in args.security_issue.lower():
        status = fix_cve(args.security_issue, args.dry_run, cfg)
    else:
        status = fix_usn(
            args.security_issue, args.dry_run, args.no_related, cfg
        )

    return status.exit_code