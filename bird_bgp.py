#
# Copyright (c) 2016 Travelping GmbH <copyright@travelping.com>
# by Tobias Hintze <tobias.hintze@travelping.com>
#
# This code is inspired and partially copied from
# https://r3blog.nl/index.php/archives/2011/02/24/bgp4-mib-support-for-bird/
# That original code does not clearly declare any license.
#
# This code also uses python-agentx library licensed under GPLv3
# (see agentx.py for details)
#
# So this code is licensed under the GPLv3 (see COPYING.GPLv3).
#

from __future__ import print_function
from adv_agentx import AgentX
from adv_agentx import SnmpGauge32, SnmpCounter32
import time
import os
import functools

from birdagent import BirdAgent

# handle get and getnext requests


def OnSnmpRead(req, ax, axd):
    pass

# handle set requests


def OnSnmpWrite(req, ax, axd):
    pass

# handle get, getnext and set requests


def OnSnmpRequest(req, ax, axd):
    pass

# initialize any ax and axd dependant code here


def OnInit(ax, axd):
    pass

# register some variables
# this function is called when a new snmp request has been received and
# if CacheInterval has expired at that time


def OnUpdate(ax, axd, state):
    print('updated bird-bgp state: {0}'.format(time.time()))

    # register variables
    axd.RegisterVar('bgp', 0)
    axd.RegisterVar('bgpVersion', "10")
    axd.RegisterVar('bgpLocalAs', 0)
    axd.RegisterVar('bgpLocalAs.0', state.get("bgpLocalAs"))

    # reindex by bgpPeerRemoteAddr
    peers = {}
    for peer in list(state["bgp-peers"].values()):
        peers[peer.get("bgpPeerIdentifier")] = peer

    for snmpkey in BirdAgent.bgp_keys:
        axd.RegisterVar(snmpkey, 0)
        for peer in sorted(list(peers.keys()), key=functools.cmp_to_key(BirdAgent.ipCompare)):
            oid = "%s.%s" % (snmpkey, peer)
            if snmpkey in peers[peer]:
                axd.RegisterVar(oid, peers[peer][snmpkey])
            else:
                axd.RegisterVar(oid, BirdAgent.bgp_defaults[snmpkey])
    return


# main program
if __name__ == '__main__':
    print('bird-bgp-agent AgentX starting')

    bird = BirdAgent(
        os.environ.get("BIRDCONF") or "/etc/bird.conf",
        os.environ.get("BIRDCLI") or "/usr/sbin/birdc",
        os.environ.get("SSCMD") or "ss -tan -o state established '( dport = :bgp or sport = :bgp )'")

    callbacks = {
        "OnSnmpRead": OnSnmpRead,
        "OnSnmpWrite": OnSnmpWrite,
        "OnSnmpRequest": OnSnmpRequest,
        "OnInit": OnInit,
        "OnUpdate": lambda ax, axd: OnUpdate(ax, axd, bird.getBGPState())
    }

    # initialize agentx module and run main loop
    try:
        AgentX(
            callbacks,
            Name='bird-bgp',
            MIBFile=os.environ.get(
                "BGPMIBFILE") or "/var/lib/mibs/ietf/BGP4-MIB",
            RootOID='BGP4-MIB::bgp',  # https://tools.ietf.org/html/draft-ietf-idr-bgp4-mib-06
            CacheInterval=int(os.environ.get("AGENTCACHEINTERVAL") or "30")
        )
    except KeyboardInterrupt:
        print('bird-bgp-agent AgentX terminating')
