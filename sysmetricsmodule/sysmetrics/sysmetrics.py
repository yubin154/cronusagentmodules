#!/usr/bin/env python
#
#  Copyright (c) 2011-2013 Corey Goldberg (http://goldb.org)
#
#  This file is part of linux-metrics
#
#  License :: OSI Approved :: MIT License:
#      http://www.opensource.org/licenses/mit-license
# 
#      Permission is hereby granted, free of charge, to any person obtaining a copy
#      of this software and associated documentation files (the "Software"), to deal
#      in the Software without restriction, including without limitation the rights
#      to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#      copies of the Software, and to permit persons to whom the Software is
#      furnished to do so, subject to the following conditions:
#
#      The above copyright notice and this permission notice shall be included in
#      all copies or substantial portions of the Software.
#
""" example usage of linux-metrics """


import linux_metrics as lm
import logging
import os
from pylons import request, response

from agent.lib.result import doneResult
from agent.lib.modulebasecontroller import ModuleBaseController

LOG = logging.getLogger("module")

class SysMetricsController(ModuleBaseController):

    def index(self):
        return 'Inside SysMetricsController index ' + os.getcwd()

    def getSysMetrics(self):
        result = SysMetricsController.collectMetrics()
        return doneResult(request, response, result = result, controller = self)
    
    @staticmethod
    def collectMetrics():
        """ collect metrics """
        result = {}
        # cpu
        cpuTimeItms = ['user', 'nice', 'system', 'idle', 'iowait']
        cpuTimes = lm.cpu_stat.cpu_times()
        cpuPcts = lm.cpu_stat.cpu_percents(sample_duration=1)
        for _, itm in enumerate(cpuTimeItms):
            result['cpu.times.%s' % itm] = cpuTimes[_]
            result['cpu.pcts.%s' % itm] = '%.2f' % cpuPcts[itm]
        result['cpu.busy'] = '%.2f' % (100 - cpuPcts['idle']) 
        result['cpu.running_procs'] = '%s' % lm.cpu_stat.procs_running()
        result['cpu.blocked_procs'] = '%s' % lm.cpu_stat.procs_blocked()
        loadAvgItms = ['1m', '5m', '15m']
        cpuLoadAvgs = lm.cpu_stat.load_avg()
        for _, itm in enumerate(loadAvgItms):
            result['cpu.load_avg_pct.%s' % itm] = '%s' % cpuLoadAvgs[_]
    
        # disk
        disk_1 = 'sda1'
        result['disk.busy'] =  '%s' % lm.disk_stat.disk_busy('sda', sample_duration=1)
        r, w = lm.disk_stat.disk_reads_writes(disk_1)    
        result['disk.reads'] = '%s' % r
        result['disk.writes'] = '%s' % w
        result['disk.used_pct.root'] = '%s' % lm.disk_stat.disk_usage('/')[4]
        result['disk.used_pct.var'] = '%s' % lm.disk_stat.disk_usage('/var')[4]
    
        # memory
        used, total, _, _, _, _ = lm.mem_stat.mem_stats()
        result['mem.used'] = '%s' % used
        result['mem.total'] = '%s' % total

        # network
        ifc_1 = 'eth0'
        rx_bytes, tx_bytes = lm.net_stat.rx_tx_bytes(ifc_1)   
        result['net.bytes_received'] = '%s' % rx_bytes
        result['net.bytes_sent'] = '%s' % tx_bytes 
        return result
        
    
if __name__ == '__main__':
    print SysMetricsController.collectMetrics()