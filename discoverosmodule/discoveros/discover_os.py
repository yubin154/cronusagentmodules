import logging
import os, sys, platform, subprocess
from agent.lib.modulebasecontroller import ModuleBaseController

LOG = logging.getLogger("module")

class DiscoverOs(ModuleBaseController):

    def __init__(self):
        ModuleBaseController.__init__(self)

    def index(self):
        return 'Inside TestService MyController index ' + os.getcwd()

    def getOsInfo(self):
        osPlatform = platform.platform().upper()
        if osPlatform.find("ESX") > 0:
            modulename = 'discoveros.discover_os_info_esx'
            __import__(modulename)
            module = sys.modules[modulename]
            return module.print_output()
        else:
            cmd = 'sudo dmidecode -s system-manufacturer'
            proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            strOsType = proc.communicate()[0]
            if strOsType.find("VMware") >= 0:
                modulename = 'discoveros.discover_os_info_vm'
                __import__(modulename)
                module = sys.modules[modulename]
                return module.print_output()
            else:
                modulename = 'discoveros.discover_os_info'
                __import__(modulename)
                module = sys.modules[modulename]
                return module.print_output()
        return 'Inside discoverService discoverService getOsInfo'




