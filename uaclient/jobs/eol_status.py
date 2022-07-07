from uaclient import util
from uaclient.config import UAConfig
from uaclient.entitlements.esm import ESMInfraEntitlement


def check_eol_and_update(cfg: UAConfig) -> bool:
    if cfg.is_attached:
        return True
    series = util.get_platform_info()["series"]
    if not util.is_active_esm(series):
        return True
    ESMInfraEntitlement().setup_unauthenticated_repo()
    return True
