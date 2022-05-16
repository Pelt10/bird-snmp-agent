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

"""
birdagent - agentx code for the bird routing daemon
	used by bird_bgp - for the bgp4-mib
"""
from __future__ import print_function

import ipaddress
from adv_agentx import SnmpGauge32, SnmpCounter32, SnmpIpAddress
import sys
import re
import subprocess
import glob
import os
import dateutil.parser
from datetime import datetime
import traceback
import pytz
from tzlocal import get_localzone


class BirdAgent(object):
    def __init__(self, cfgfile, birdcli, sscmd):
        self.cfgfile = cfgfile
        self.birdcli = birdcli
        self.sscmd = sscmd

    bgp_states = {
        "idle": 1,
        "connect": 2,
        "active": 3,
        "opensent": 4,
        "openconfirm": 5,
        "established": 6,
    }
    _re_ipv4 = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
    _re_ipv6 = re.compile(r"^[\da-fA-F:]+$")
    _re_ipv4_or_v6 = "((\[?((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\]?)|([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+))"
    _re_config_include = re.compile("^include\s*\"([^\"]*)\".*$")
    _re_config_bgp_proto_begin = re.compile("^protocol bgp ([a-zA-Z0-9_]+).*\{$")
    _re_config_bgp_holdtime = re.compile("hold time ([0-9]+);")
    _re_config_bgp_keepalive = re.compile("keepalive time ([0-9]+);")
    _re_config_timeformat = re.compile(
        "\s*timeformat\s+protocol\s+iso\s+long\s+;")
    _re_config_proto_end = re.compile("^\}$")

    _re_birdcli_bgp_begin = re.compile(
        "^([a-zA-Z0-9_]+)\s+BGP\s+[a-zA-Z0-9-_]+\s+[a-zA-Z0-9]+\s+(\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d).*$")
    _re_birdcli_bgp_peer = {
        "bgpPeerIdentifier": re.compile("^\s+Neighbor ID:\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$"),
        "bgpPeerState": re.compile("^\s+BGP state:\s+([a-zA-Z]+)$"),
        "bgpPeerLocalAddr": re.compile("^\s+Source address:\s+%s$" % _re_ipv4_or_v6),
        "bgpPeerLocalAs": re.compile("^\s+Local AS:\s+([0-9]+)$"),
        "bgpPeerRemoteAddr": re.compile("^\s+Neighbor address:\s+%s$" % _re_ipv4_or_v6),
        "bgpPeerRemoteAs": re.compile("^\s+Neighbor AS:\s+([0-9]+)$"),
        "bgpPeerInUpdates": re.compile("^\s+Import updates:\s+([0-9]+)\s+[0-9\-]+\s+[0-9\-]+\s+[0-9\-]+\s+[0-9\-]+$"),
        "bgpPeerOutUpdates": re.compile("^\s+Export updates:\s+([0-9]+)\s+[0-9\-]+\s+[0-9\-]+\s+[0-9\-]+\s+[0-9\-]+$"),
        "bgpPeerHoldTime": re.compile("^\s+Hold timer:\s+([0-9]+.[0-9]+)\/[0-9]+$"),
        "bgpPeerHoldTimeConfigured": re.compile("^\s+Hold timer:\s+[0-9]+.[0-9]+\/([0-9]+)$"),
        "bgpPeerKeepAlive": re.compile("^\s+Keepalive timer:\s+([0-9]+.[0-9]+)\/[0-9]+$"),
        "bgpPeerKeepAliveConfigured": re.compile("^\s+Keepalive timer:\s+[0-9]+.[0-9]+\/([0-9]+)$"),
        "bgpPeerLastError": re.compile("^\s+Last error:\s+([a-zA-Z0-9-_\ ]+)$")}
    _re_birdcli_bgp_end = re.compile("^$")

    _re_ss = re.compile(
        "^[0-9]+\s+[0-9]+\s+\[?(?P<src_addr>([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:)|([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:)|([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:)|([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)|([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)|([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)|([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)|:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)(%.+)?|\d+\.\d+\.\d+\.\d+)\]?(%[a-z0-9-\.]+)?:(?P<src_port>[0-9]+)\s+\[?(?P<dst_addr>([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:)|([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:)|([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:)|([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)|([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)|([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)|([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)|:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)(%.+)?|\d+\.\d+\.\d+\.\d+)\]?(%[a-z0-9-\.]+?)?:(?P<dst_port>[0-9]+)"
    )

    bgp_keys = [
        'bgpPeerIdentifier',
        'bgpPeerState',
        'bgpPeerAdminStatus',
        'bgpPeerNegotiatedVersion',
        'bgpPeerLocalAddr',
        'bgpPeerLocalPort',
        'bgpPeerRemoteAddr',
        'bgpPeerRemotePort',
        'bgpPeerRemoteAs',
        'bgpPeerInUpdates',
        'bgpPeerOutUpdates',
        'bgpPeerInTotalMessages',
        'bgpPeerOutTotalMessages',
        'bgpPeerLastError',
        'bgpPeerFsmEstablishedTransitions',
        'bgpPeerFsmEstablishedTime',
        'bgpPeerConnectRetryInterval',
        'bgpPeerHoldTime',
        'bgpPeerKeepAlive',
        'bgpPeerHoldTimeConfigured',
        'bgpPeerKeepAliveConfigured',
        'bgpPeerMinASOriginationInterval',
        'bgpPeerMinRouteAdvertisementInterval',
        'bgpPeerInUpdateElapsedTime',
    ]

    bgp_defaults = {
        'bgpPeerIdentifier': SnmpIpAddress("0.0.0.0"),
        'bgpPeerLocalAddr': SnmpIpAddress("0.0.0.0"),
        'bgpPeerLocalPort': 0,
        'bgpPeerRemoteAs': 0,
        'bgpPeerRemotePort': 0,
        'bgpPeerHoldTime': 0,
        'bgpPeerHoldTimeConfigured': 0,
        'bgpPeerKeepAlive': 0,
        'bgpPeerKeepAliveConfigured': 0,
        'bgpPeerState': 1,
        'bgpPeerInUpdates': SnmpCounter32(0),
        'bgpPeerOutUpdates': SnmpCounter32(0),
        'bgpPeerAdminStatus': 2,
        'bgpPeerConnectRetryInterval': 0,
        'bgpPeerFsmEstablishedTime': SnmpGauge32(0),
        'bgpPeerFsmEstablishedTransitions': SnmpCounter32(0),
        'bgpPeerInTotalMessages': SnmpCounter32(0),
        'bgpPeerInUpdateElapsedTime': SnmpGauge32(0),
        'bgpPeerLastError': '0',
        'bgpPeerMinASOriginationInterval': 15,
        'bgpPeerMinRouteAdvertisementInterval': 30,
        'bgpPeerNegotiatedVersion': 0,
        'bgpPeerOutTotalMessages': SnmpCounter32(0),
    }

    @staticmethod
    def ipCompare(ip1, ip2):
        ip1_o = ipaddress.ip_address(ip1)
        ip2_o = ipaddress.ip_address(ip2)
        if type(ip1_o) != type(ip2_o):
            return 1 if type(ip1_o) == ipaddress.IPv4Address else -1
        return (ip1_o > ip2_o) - (ip1_o < ip2_o)

    @staticmethod
    def combinedConfigLines(filename):
        """
        yield the whole bird configuration file line by line;
        all include-statements are resolved/unrolled
        """
        try:
            with open(filename, "r") as bird_conf:
                for line in bird_conf:
                    line = line.strip()
                    match = BirdAgent._re_config_include.search(line)
                    if not match:
                        yield line
                    else:
                        included = match.group(1)
                        if not included.startswith('/'):
                            included = os.path.join(os.path.dirname(filename), included)
                        for subconf in glob.glob(included):
                            yield "# subconf: %s (from %s)" % (subconf, line)
                            for subline in BirdAgent.combinedConfigLines(subconf):
                                yield subline
        except IOError:
            print("ERROR: Unable to open %s, terminating..." % filename)
            sys.exit(1)
        except Exception as e:
            print(
                "ERROR: Unexpected error in combinedConfigLines(): [%s], terminating" % e)
            sys.exit(1)

    @staticmethod
    def bgpKeys():
        return BirdAgent.bgp_keys

    def getBGPState(self):
        """
        fetch BGP-related state from:
        * parsing configuration file
        * parsing `birdc show protocols all` output
        * parsing `ss` output
        """

        timezone = get_localzone()
        current_time = datetime.now(pytz.utc)

        # fetch some data from the configuration:
        cfg = {"bgp-peers": {}}
        proto = None
        for line in BirdAgent.combinedConfigLines(self.cfgfile):
            if self._re_config_timeformat:
                cfg["timeformat"] = True
            match = self._re_config_bgp_proto_begin.search(line)
            if match:
                proto = match.group(1)
                cfg["bgp-peers"][proto] = {}
            if proto:
                match = self._re_config_bgp_holdtime.search(line)
                if match:
                    cfg["bgp-peers"][proto]["bgpPeerHoldTimeConfigured"] = int(
                        match.group(1))

                match = self._re_config_bgp_keepalive.search(line)
                if match:
                    cfg["bgp-peers"][proto]["bgpPeerKeepAliveConfigured"] = int(
                        match.group(1))

            if self._re_config_proto_end.search(line):
                proto = None

        if "timeformat" not in cfg:
            print("ERROR: timeformat not configured for this agent's use, terminating...")
            sys.exit(1)

        state = cfg.copy()
        bgp_proto = None
        # "with"-context-manager for Popen not available in python < 3.2
        birdc = subprocess.Popen([self.birdcli, "show", "protocols", "all"],
                                 stdout=subprocess.PIPE)
        output = birdc.communicate()[0].decode('utf-8', 'ignore')
        if birdc.returncode != 0:
            print(
                "ERROR: bird-CLI %s failed: %i" %
                (self.birdcli, birdc.returncode))

        for line in output.split("\n"):
            match = self._re_birdcli_bgp_begin.search(line)
            if match:
                bgp_proto = match.group(1)
                timestamp = dateutil.parser.parse(match.group(2))
                if not timestamp.tzinfo:
                    timestamp = timezone.localize(timestamp)
                if bgp_proto not in state["bgp-peers"]:
                    print(
                        "WARNING: proto \"%s\" not in config, skipping" %
                        bgp_proto)
                    bgp_proto = None
                    continue
                state["bgp-peers"][bgp_proto]["bgpPeerFsmEstablishedTime"] = SnmpGauge32(
                    abs(current_time - timestamp).total_seconds())
            if bgp_proto:
                peerprop_name = None
                try:
                    for peerprop_name, peerprop_re in list(
                            self._re_birdcli_bgp_peer.items()):
                        match = peerprop_re.search(line)
                        if match:
                            if peerprop_name == 'bgpPeerState':
                                if not match.group(1).lower() == 'down':
                                    state["bgp-peers"][bgp_proto][peerprop_name] = \
                                        self.bgp_states[match.group(1).lower()]
                                else:
                                    # handle disabled (down) protocols
                                    state["bgp-peers"][bgp_proto][peerprop_name] = int(
                                        1)
                                    state["bgp-peers"][bgp_proto]["bgpPeerAdminStatus"] = int(
                                        1)
                                    state["bgp-peers"][bgp_proto]["bgpPeerFsmEstablishedTime"] = int(
                                        0)

                            elif peerprop_name in [
                                'bgpPeerIdentifier',
                                'bgpPeerLocalAddr',
                                'bgpPeerRemoteAddr'
                            ]:
                                state["bgp-peers"][bgp_proto][peerprop_name] = SnmpIpAddress(
                                    match.group(1))
                            elif peerprop_name in [
                                'bgpPeerInUpdates',
                                'bgpPeerOutUpdates'
                            ]:
                                state["bgp-peers"][bgp_proto][peerprop_name] = SnmpCounter32(
                                    match.group(1))
                            elif peerprop_name in [
                                "bgpPeerHoldTime",
                                "bgpPeerHoldTimeConfigured",
                                "bgpPeerKeepAlive",
                                "bgpPeerKeepAliveConfigured"
                            ]:
                                state["bgp-peers"][bgp_proto][peerprop_name] = int(float(match.group(1)))
                            else:
                                state["bgp-peers"][bgp_proto][peerprop_name] = int(
                                    match.group(1))
                except Exception as e:
                    print("WARNING: Unable to process \"%s\" as \"%s\" for protocol \"%s\": %s" %
                          (match.group(1), peerprop_name, bgp_proto, e))

            if self._re_birdcli_bgp_end.search(line):
                bgp_proto = None

        local_as = set(peer["bgpPeerLocalAs"] for peer in state["bgp-peers"].values())
        try:
            state["bgpLocalAs"] = min(local_as)
            if len(local_as) > 1:
                print("WARNING: multiple local AS: %s; using %i" % (
                    ", ".join(str(asn) for asn in local_as), state["bgpLocalAs"])
                      )
        except ValueError:
            print("ERROR: No local AS found, terminating...")
            sys.exit(1)

        # use ss to query for source and destination ports of the bgp protocols
        bgp_sessions = {}
        try:
            ss = subprocess.Popen(self.sscmd, shell=True,
                                  stdout=subprocess.PIPE)

            for line in ss.communicate()[0].decode('utf-8', 'ignore').split("\n"):
                match = self._re_ss.search(line)
                if not match:
                    continue
                # key 4-tuples by remote ip: src-addr, src-port, dst-addr, dst-port
                for proto, session in state["bgp-peers"].items():
                    if session["bgpPeerRemoteAddr"] == match.group("dst_addr"):
                        bgp_sessions[proto] = (
                            match.group("src_addr"),
                            match.group("src_port"),
                            match.group("dst_addr"),
                            match.group("dst_port")
                        )
        except subprocess.CalledProcessError as e:
            print(
                "ERROR: Error executing \"ss\" command [%s], terminating..." % e)
            sys.exit(1)

        # match the connection 4-tuples with bgp-state
        for proto in list(state["bgp-peers"].keys()):
            if not state["bgp-peers"][proto]:
                continue

            # enrich the state by local+remote ports
            try:
                srcip, srcport, dstip, dstport = bgp_sessions[proto]
            except:
                print("INFO: Protocol \"%s\" has no active BGP session." % proto)
                try:
                    state["bgp-peers"][proto]["bgpPeerRemoteAddr"] = \
                        cfg["bgp-peers"][proto]["bgpPeerRemoteAddr"]
                    continue
                except:
                    state["bgp-peers"][proto]["bgpPeerRemoteAddr"] = SnmpIpAddress(
                        "0.0.0.0")
                    continue

            # Check for mismatch between config and ss output
            if srcip != state["bgp-peers"][proto]["bgpPeerLocalAddr"] or \
                    dstip != state["bgp-peers"][proto]["bgpPeerRemoteAddr"]:
                print(
                    "WARNING: Protocol \"%s\" has mismatch between the configuration file (local: %s, neighbor %s) and the active BGP session (local: %s, neighbor: %s)" %
                    (proto, state["bgp-peers"][proto]["bgpPeerLocalAddr"],
                     state["bgp-peers"][proto]["bgpPeerRemoteAddr"], srcip, dstip))
                continue

            # populate the ports
            state["bgp-peers"][proto]["bgpPeerLocalPort"] = int(srcport)
            state["bgp-peers"][proto]["bgpPeerRemotePort"] = int(dstport)

        return state
