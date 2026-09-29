"""Builtin (tier-2) adapters and the tier-1 OpenConfig adapter."""

from inv4r.adapters.builtin.base_builtin import BuiltinParser, make_fact
from inv4r.adapters.builtin.cisco_ios import CiscoIOSAdapter
from inv4r.adapters.builtin.juniper_junos import JuniperJunosAdapter
from inv4r.adapters.builtin.fortinet_fortigate import FortinetFortigateAdapter
from inv4r.adapters.builtin.paloalto_panos import PaloAltoPanosAdapter
from inv4r.adapters.builtin.arista_eos import AristaEOSAdapter
from inv4r.adapters.builtin.sonic import SonicAdapter
from inv4r.adapters.builtin.aws_security_group import AwsSecurityGroupAdapter
from inv4r.adapters.builtin.openconfig import OpenConfigAdapter


def default_adapters():
    """Adapter stack in resolution order-independent form; resolver picks by tier."""
    return [
        OpenConfigAdapter(),
        CiscoIOSAdapter(),
        JuniperJunosAdapter(),
        FortinetFortigateAdapter(),
        PaloAltoPanosAdapter(),
        AristaEOSAdapter(),
        SonicAdapter(),
        AwsSecurityGroupAdapter(),
    ]


__all__ = [
    "AristaEOSAdapter", "AwsSecurityGroupAdapter", "BuiltinParser",
    "CiscoIOSAdapter", "FortinetFortigateAdapter", "JuniperJunosAdapter",
    "OpenConfigAdapter", "PaloAltoPanosAdapter", "SonicAdapter",
    "default_adapters", "make_fact",
]
