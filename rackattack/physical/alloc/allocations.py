from rackattack.physical.alloc import allocation
from rackattack.physical.alloc import priority
from rackattack.common import globallock
from rackattack.virtual import sh
import logging


class Allocations:
    def __init__(self, broadcaster, hosts, freePool, osmosisServer):
        self._broadcaster = broadcaster
        self._hosts = hosts
        self._freePool = freePool
        self._osmosisServer = osmosisServer
        self._allocations = []
        self._index = 1

    def create(self, requirements, allocationInfo):
        logging.info("Allocation requested: '%(requirements)s' '%(allocationInfo)s'", dict(
            requirements=requirements, allocationInfo=allocationInfo))
        assert globallock.assertLocked()
        self._cleanup()
        self._verifyLabelsExistsInOsmosis([r['imageLabel'] for r in requirements.values()])
        priorityInstance = priority.Priority(
            requirements=requirements, allocationInfo=allocationInfo,
            freePool=self._freePool, allocations=self._allocations)
        allocated = priorityInstance.allocated()
        try:
            alloc = allocation.Allocation(
                index=self._index, requirements=requirements, allocationInfo=allocationInfo,
                allocated=allocated, broadcaster=self._broadcaster, freePool=self._freePool)
        except:
            logging.error("Creating allocation fails, freeing up all allocated hosts")
            for allocated in allocated.values():
                self._freePool.put(allocated)
            raise
        self._allocations.append(alloc)
        self._index += 1
        logging.info("Allocation granted: %(allocated)s", dict(
            allocated={k: v.hostImplementation().id() for k, v in alloc.allocated().iteritems()}))
        return alloc

    def byIndex(self, index):
        assert globallock.assertLocked()
        self._cleanup()
        for alloc in self._allocations:
            if alloc.index() == index:
                return alloc
        raise IndexError("No such allocation")

    def all(self):
        assert globallock.assertLocked()
        self._cleanup()
        return self._allocations

    def _cleanup(self):
        self._allocations = [a for a in self._allocations if not a.deadForAWhile()]

    def _verifyLabelsExistsInOsmosis(self, labels):
        for label in labels:
            exists = sh.run([
                "osmosis", "listlabels", label, "--objectStores", self._osmosisServer + ":1010"]).strip()
            if not exists:
                raise Exception("Label '%s' does not exist on object store" % label)
