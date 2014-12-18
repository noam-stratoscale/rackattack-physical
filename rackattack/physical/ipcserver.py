import threading
import zmq
import logging
import simplejson
from rackattack.tcp import heartbeat
from rackattack.tcp import suicide
from rackattack import api
from rackattack.common import globallock
from rackattack.physical import network


class IPCServer(threading.Thread):
    def __init__(self, tcpPort, publicIP, osmosisServerIP, allocations, hosts, dnsmasq):
        self._publicIP = publicIP
        self._osmosisServerIP = osmosisServerIP
        self._allocations = allocations
        self._hosts = hosts
        self._dnsmasq = dnsmasq
        self._context = zmq.Context()
        self._socket = self._context.socket(zmq.REP)
        self._socket.bind("tcp://*:%d" % tcpPort)
        threading.Thread.__init__(self)
        self.daemon = True
        threading.Thread.start(self)

    def _cmd_handshake(self, versionInfo):
        if versionInfo['RACKATTACK_VERSION'] != api.VERSION:
            raise Exception(
                "Rackattack API version on the client side is '%s', and '%s' on the provider" % (
                    versionInfo['RACKATTACK_VERSION'], api.VERSION))
        if versionInfo['ZERO_MQ']['VERSION_MAJOR'] != zmq.VERSION_MAJOR:
            raise Exception(
                "zmq version on the client side is '%s', and '%s' on the provider" % (
                    versionInfo['ZERO_MQ']['VERSION_MAJOR'], zmq.VERSION_MAJOR))

    def _cmd_allocate(self, requirements, allocationInfo):
        allocation = self._allocations.create(requirements, allocationInfo)
        return allocation.index()

    def _cmd_allocation__nodes(self, id):
        allocation = self._allocations.byIndex(id)
        if allocation.dead():
            raise Exception("Must not fetch nodes from a dead allocation")
        if not allocation.done():
            raise Exception("Must not fetch nodes from a not done allocation")
        result = {}
        for name, stateMachine in allocation.allocated().iteritems():
            host = stateMachine.hostImplementation()
            result[name] = dict(
                id=host.id(),
                primaryMACAddress=host.primaryMACAddress(),
                secondaryMACAddress=host.secondaryMACAddress(),
                ipAddress=host.ipAddress(),
                netmask=network.NETMASK,
                inauguratorServerIP=network.GATEWAY_IP_ADDRESS,
                gateway=network.GATEWAY_IP_ADDRESS,
                osmosisServerIP=self._osmosisServerIP)
        return result

    def _cmd_allocation__free(self, id):
        allocation = self._allocations.byIndex(id)
        allocation.free()

    def _cmd_allocation__done(self, id):
        allocation = self._allocations.byIndex(id)
        return allocation.done()

    def _cmd_allocation__dead(self, id):
        allocation = self._allocations.byIndex(id)
        return allocation.dead()

    def _cmd_heartbeat(self, ids):
        for id in ids:
            allocation = self._allocations.byIndex(id)
            allocation.heartbeat()
        return heartbeat.HEARTBEAT_OK

    def _cmd_disablepxe(self, mac):
        self._dnsmasq.ignorePXEforSpecificMac(mac)

    def _cmd_enablepxe(self, mac):
        self._dnsmasq.removeIgnorePXEforSpecificMac(mac)

    def _findNode(self, allocationID, nodeID):
        allocation = self._allocations.byIndex(allocationID)
        for stateMachine in allocation.inaugurated().values():
            if stateMachine.hostImplementation().id() == nodeID:
                return stateMachine
        raise Exception("Node with id '%s' was not found in this allocation" % nodeID)

    def _cmd_node__rootSSHCredentials(self, allocationID, nodeID):
        stateMachine = self._findNode(allocationID, nodeID)
        credentials = stateMachine.hostImplementation().rootSSHCredentials()
        return network.translateSSHCredentials(
            stateMachine.hostImplementation().index(), credentials, self._publicIP)

    def _cmd_node__coldRestart(self, allocationID, nodeID):
        stateMachine = self._findNode(allocationID, nodeID)
        logging.info("Cold restarting node %(node)s by allocator request", dict(node=nodeID))
        stateMachine.hostImplementation().coldRestart()

    def run(self):
        try:
            while True:
                try:
                    self._work()
                except:
                    logging.exception("Handling")
        except:
            logging.exception("Virtual IPC server aborts")
            suicide.killSelf()
            raise

    def _work(self):
        message = self._socket.recv(0)
        try:
            incoming = simplejson.loads(message)
            handler = getattr(self, "_cmd_" + incoming['cmd'])
            with globallock.lock:
                response = handler(** incoming['arguments'])
        except Exception, e:
            logging.exception('Handling')
            response = dict(exceptionString=str(e), exceptionType=e.__class__.__name__)
        try:
            json = simplejson.dumps(response)
        except Exception, e:
            logging.exception('Encoding cmd: %(cmd)s', dict(cmd=incoming['cmd']))
            json = simplejson.dumps(dict(exceptionString=str(e), exceptionType=e.__class__.__name__))
        self._socket.send(json)

    def _cmd_admin__queryStatus(self):
        allocations = [dict(
            index=a.index(),
            allocationInfo=a.allocationInfo(),
            allocated={k: v.hostImplementation().index() for k, v in a.allocated().iteritems()},
            done=a.dead() or a.done(),
            dead=a.dead()
            ) for a in self._allocations.all()]
        STATE = {
            1: "QUICK_RECLAIMATION_IN_PROGRESS",
            2: "SLOW_RECLAIMATION_IN_PROGRESS",
            3: "CHECKED_IN",
            4: "INAUGURATION_LABEL_PROVIDED",
            5: "INAUGURATION_DONE",
            6: "DESTROYED"}
        hosts = [dict(
            index=s.hostImplementation().index(),
            id=s.hostImplementation().id(),
            primaryMACAddress=s.hostImplementation().primaryMACAddress(),
            secondaryMACAddress=s.hostImplementation().secondaryMACAddress(),
            ipAddress=s.hostImplementation().ipAddress(),
            state=STATE[s.state()]
            ) for s in self._hosts.all()]
        return dict(allocations=allocations, hosts=hosts)
