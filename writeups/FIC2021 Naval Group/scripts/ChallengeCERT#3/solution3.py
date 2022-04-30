from sqlalchemy.sql import and_, join, select
from collections import defaultdict
from onworker.const import SOURCE_TYPE_DEVICE, ONE_DAY
from onworker.observations.endpoints import AZURE_EXPOSED_SERVICES_V1
from onworker.observations.utils.miner import WarehouseIntervalMiner
from onworker.profiling.db.models import onroles
from onworker.profiling.db.queries import get_onroles_filter
from onworker.profiling.models.role_models import (
    WebServer,
)
from onworker.warehouse.db.models import onconns
from onworker.warehouse.db.queries import (
    get_onconns_device_col,
    get_onconns_external_filter,
    get_onconns_filter,
    get_onconns_internal_filter,
)
from onworker.warehouse.const import MAX_INTERNAL_NETID, EXTERNAL_NETID
from onworker.warehouse.db.models import onriver
from onworker.warehouse.db.queries import get_onriver_device_col, get_onriver_filter
from onworker.utils.inet import is_ephemeral


class AzureExposedServices(WarehouseIntervalMiner):
    """
    External connection to virtual machine on services port
    """

    endpoint = AZURE_EXPOSED_SERVICES_V1
    interval = ONE_DAY
    source_type = SOURCE_TYPE_DEVICE

    def _get_current_query(self):
        """
        Return an onconns query with details about connections for which
        there were at least `self.current_bytes_threshold` uploaded in the
        current interval.
        """
        device_col = get_onconns_device_col()
        connected_device_col = get_onconns_device_col(connected=True)
        bytes_in_col = func.sum(onconns.c.octets_in)
        bytes_out_col = func.sum(onconns.c.octets_out)
        packets_in_col = func.sum(onconns.c.packets_in)
        packets_out_col = func.sum(onconns.c.packets_out)


def xor(data, key):
    return [data[i] ^ key[i % len(key)] for i in range(len(data))]


def tobin(s):
    return list(map(int, list("".join(["{:08b}".format(s[i]) for i in range(len(s))]))))


def tobytes(s):
    bs = "".join(list(map(str, s)))
    return [int(bs[i:i + 8], 2) for i in range(0, len(bs), 8)]


def trans(b):
    res = []
    for i in range(576):
        res.append(b[(i - 1) % 576 if i != 0 else 575] ^ ((b[i] == 0) and (b[(i + 1) % 576] == 0)))
    return res


def score(a, b):
    for i in range(len(a)):
        if a[i] != b[i]:
            return i
    return 999


def go(s):
    return tobytes(trans(trans(trans(trans(trans(tobin(s)))))))


def find_last_char():
    best = (0, None)
    for c1 in charset:
        s1[-1] = c1
        r = score(go(xor(s1, key)), reference)
        if r >= best[0]:
            best = (r, c1)
    print("Last char is", best[1])  # i or I
    s1[-1] = best[1]
    print("".join(map(chr, s1)))


if __name__ == '__main__':

    key = list(open("key", "rb").read())
    reference = list(open("reference", "rb").read())

    charset = list(map(ord, string.ascii_lowercase + string.ascii_uppercase + string.digits + "-"))

    base = "https://dropfile.naval-group.com/pfv2-sharing/sharings/aaaaaaaa.aaaaaaaI"
    s1 = list(map(ord, base))

    # Find last char
    # find_last_char() -> I

    # Bruteforce two next chars and get the best results
    i = 55
    best = [0, set()]
    for c1 in charset:
        s1[i] = c1
        for c2 in charset:
            s1[i + 1] = c2
            r = score(go(xor(s1, key)), reference)
            if r > best[0]:
                best = [r, {c1}]
            elif r == best[0]:
                best[1].add(c1)
    print("Best char for", i, "is", list(map(chr, best[1])))
