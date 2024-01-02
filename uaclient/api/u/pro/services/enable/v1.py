import logging
from typing import List, Optional

from uaclient import entitlements, event_logger, lock, messages, util
from uaclient.api import exceptions
from uaclient.api.api import APIEndpoint
from uaclient.api.data_types import AdditionalInfo
from uaclient.api.u.pro.status.enabled_services.v1 import _enabled_services
from uaclient.api.u.pro.status.is_attached.v1 import _is_attached
from uaclient.config import UAConfig
from uaclient.data_types import (
    BoolDataValue,
    DataObject,
    Field,
    StringDataValue,
    data_list,
)

event = event_logger.get_event_logger()
LOG = logging.getLogger(util.replace_top_level_logger_name(__name__))


class EnableOptions(DataObject):
    fields = [
        Field("service", StringDataValue),
        Field("variant", StringDataValue, False),
        Field("enable_required_services", BoolDataValue, False),
        Field("disable_incompatible_services", BoolDataValue, False),
        Field("access_only", BoolDataValue, False),
    ]

    def __init__(
        self,
        *,
        service: str,
        variant: Optional[str] = None,
        enable_required_services: bool = True,
        disable_incompatible_services: bool = True,
        access_only: bool = False
    ):
        self.service = service
        self.variant = variant
        self.enable_required_services = enable_required_services
        self.disable_incompatible_services = disable_incompatible_services
        self.access_only = access_only


class EnableResult(DataObject, AdditionalInfo):
    fields = [
        Field("enabled", data_list(StringDataValue)),
        Field("disabled", data_list(StringDataValue)),
        Field("reboot_required", BoolDataValue),
        Field("messages", data_list(StringDataValue)),
    ]

    def __init__(
        self,
        *,
        enabled: List[str],
        disabled: List[str],
        reboot_required: bool,
        messages: List[str]
    ):
        self.enabled = enabled
        self.disabled = disabled
        self.reboot_required = reboot_required
        self.messages = messages


def _enabled_services_names(cfg: UAConfig) -> List[str]:
    return [s.name for s in _enabled_services(cfg).enabled_services]


def enable(options: EnableOptions) -> EnableResult:
    return _enable(options, UAConfig())


def _enable(
    options: EnableOptions,
    cfg: UAConfig,
) -> EnableResult:
    event.set_event_mode(event_logger.EventLoggerMode.JSON)

    if not util.we_are_currently_root():
        raise exceptions.NonRootUserError()

    if not _is_attached(cfg).is_attached:
        raise exceptions.UnattachedError()

    if options.service == "landscape":
        raise exceptions.NotSupported()

    enabled_services_before = _enabled_services_names(cfg)
    if options.service in enabled_services_before:
        # nothing to do
        return EnableResult(
            enabled=[],
            disabled=[],
            reboot_required=False,
            messages=[],
        )

    ent_cls = entitlements.entitlement_factory(
        cfg=cfg, name=options.service, variant=options.variant or ""
    )
    entitlement = ent_cls(
        cfg,
        assume_yes=True,
        allow_beta=True,
        called_name=options.service,
        access_only=options.access_only,
    )

    success = False
    fail_reason = None

    try:
        with lock.SpinLock(
            cfg=cfg,
            lock_holder="u.pro.services.enable.v1",
        ):
            success, fail_reason = entitlement.enable(
                enable_required_services=options.enable_required_services,
                disable_incompatible_services=options.disable_incompatible_services,  # noqa: E501
                api=True,
            )
    except Exception as e:
        lock.clear_lock_file_if_present()
        raise e

    if not success:
        if fail_reason is not None:
            reason = fail_reason.message
        else:
            reason = messages.GENERIC_UNKNOWN_ISSUE
        raise exceptions.EntitlementNotEnabledError(
            service=options.service, reason=reason
        )

    enabled_services_after = _enabled_services_names(cfg)

    post_enable_messages = [
        msg
        for msg in entitlement.messaging.get("post_enable", [])
        if isinstance(msg, str)
    ]

    return EnableResult(
        enabled=sorted(
            list(
                set(enabled_services_after).difference(
                    set(enabled_services_before)
                )
            )
        ),
        disabled=sorted(
            list(
                set(enabled_services_before).difference(
                    set(enabled_services_after)
                )
            )
        ),
        reboot_required=entitlement._check_for_reboot(),
        messages=post_enable_messages,
    )


endpoint = APIEndpoint(
    version="v1",
    name="EnableService",
    fn=_enable,
    options_cls=EnableOptions,
)
