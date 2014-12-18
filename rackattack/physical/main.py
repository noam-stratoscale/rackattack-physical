import logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
from rackattack.ssh import connection
connection.discardParamikoLogs()
connection.discardSSHDebugMessages()
import time
import argparse
from rackattack.physical import config
from rackattack.physical import network
from rackattack.physical import dynamicconfig
import rackattack.virtual.handlekill
from rackattack.common import dnsmasq
from rackattack.common import globallock
from rackattack.common import tftpboot
from rackattack.common import inaugurate
from rackattack.common import timer
from rackattack.common import hosts
from rackattack.physical.alloc import freepool
from rackattack.physical.alloc import allocations
from rackattack.physical import ipcserver
from rackattack.tcp import publish
from twisted.internet import reactor
from twisted.web import server
from rackattack.common import httprootresource
import yaml

parser = argparse.ArgumentParser()
parser.add_argument("--requestPort", default=1014, type=int)
parser.add_argument("--subscribePort", default=1015, type=int)
parser.add_argument("--httpPort", default=1016, type=int)
parser.add_argument("--rackYAML")
parser.add_argument("--serialLogsDirectory")
parser.add_argument("--managedPostMortemPacksDirectory")
parser.add_argument("--configurationFile")
args = parser.parse_args()

if args.rackYAML:
    config.RACK_YAML = args.rackYAML
if args.serialLogsDirectory:
    config.SERIAL_LOGS_DIRECTORY = args.serialLogsDirectory
if args.configurationFile:
    config.CONFIGURATION_FILE = args.configurationFile
if args.managedPostMortemPacksDirectory:
    config.MANAGED_POST_MORTEM_PACKS_DIRECTORY = args.managedPostMortemPacksDirectory

with open(config.CONFIGURATION_FILE) as f:
    conf = yaml.load(f.read())

network.setUpStaticPortForwardingForSSH(conf['PUBLIC_INTERFACE'])
timer.TimersThread()
tftpbootInstance = tftpboot.TFTPBoot(
    netmask=network.NETMASK,
    inauguratorServerIP=network.GATEWAY_IP_ADDRESS,
    osmosisServerIP=conf['OSMOSIS_SERVER_IP'],
    rootPassword=config.ROOT_PASSWORD,
    withLocalObjectStore=True)
dnsmasq.DNSMasq.eraseLeasesFile()
dnsmasq.DNSMasq.killAllPrevious()
dnsmasqInstance = dnsmasq.DNSMasq(
    tftpboot=tftpbootInstance,
    serverIP=network.GATEWAY_IP_ADDRESS,
    netmask=network.NETMASK,
    firstIP=network.FIRST_IP,
    lastIP=network.LAST_IP,
    gateway=network.GATEWAY_IP_ADDRESS,
    nameserver=network.GATEWAY_IP_ADDRESS)
inaugurateInstance = inaugurate.Inaugurate(bindHostname=network.GATEWAY_IP_ADDRESS)
publishInstance = publish.Publish(tcpPort=args.subscribePort, localhostOnly=False)
hostsInstance = hosts.Hosts()
freePool = freepool.FreePool(hostsInstance)
allocationsInstance = allocations.Allocations(
    broadcaster=publishInstance, hosts=hostsInstance, freePool=freePool,
    osmosisServer=conf['OSMOSIS_SERVER_IP'])
dynamicConfig = dynamicconfig.DynamicConfig(
    hosts=hostsInstance,
    dnsmasq=dnsmasqInstance,
    inaugurate=inaugurateInstance,
    tftpboot=tftpbootInstance,
    freePool=freePool,
    allocations=allocationsInstance)
ipcServer = ipcserver.IPCServer(
    tcpPort=args.requestPort,
    publicIP=conf['PUBLIC_IP'],
    osmosisServerIP=conf['OSMOSIS_SERVER_IP'],
    allocations=allocationsInstance,
    hosts=hostsInstance,
    dnsmasq=dnsmasqInstance)


def serialLogFilename(vmID):
    with globallock.lock:
        return hostsInstance.byID(vmID).hostImplementation().serialLogFilename()


def createPostMortemPackForAllocationID(allocationID):
    with globallock.lock:
        return allocationsInstance.byIndex(int(allocationID)).createPostMortemPack()


root = httprootresource.HTTPRootResource(
    serialLogFilename, createPostMortemPackForAllocationID,
    config.MANAGED_POST_MORTEM_PACKS_DIRECTORY)
reactor.listenTCP(args.httpPort, server.Site(root))
logging.info("Physical RackAttack up and running")
reactor.run()
