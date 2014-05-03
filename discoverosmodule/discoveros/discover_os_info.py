# discover_os_info.py
#
# script to print the details of machine and OS in JSON format
#
# supports only ubuntu
#

import commands
import json
import logging

# Kernel evaluator
uname_sr        = 'uname -s -r';
uname_ms        = 'uname -m -s';

# os version evaluator
lsb_release        = 'cat /etc/lsb-release';

# model evaluator
model            = "sudo dmidecode -s system-product-name";

# hostname evaluator
hostname        = 'hostname -f';

# fdqn evaluator
fqdn            = 'hostname -f';

# label evaluator
label            = 'hostname -f';

# primarydns & secondarydns evaluator
dns                = "awk '/nameserver/ {print $2}' /etc/resolv.conf";

# ntp service status evaluator
ntp_status        =  "/etc/init.d/ntp status | awk '{print $5}'";

# ntp drift evaluator
ntp_drift        =  "cat /var/lib/ntp/drift";

# auth evaluator
auth            =   "awk '/^passwd_compat/ {print $2}' /etc/nsswitch.conf";

#timezone evaluator
timezone        = 'cat /etc/timezone';

# cpu count
cpu_count        = "grep -c processor /proc/cpuinfo";

# serial number
serial            = "sudo /usr/sbin/dmidecode -s system-serial-number";

# memory
memory            = "awk '/MemTotal:/ {print $2}' /proc/meminfo"

# uuid
uuid            = 'sudo dmidecode -s system-uuid';

# this is to query active interfaces, for which we will query ipaddress, mac
interfaces        = " | awk '/Link encap/&&!/lo/ {print $1}'";

# this will query the ip address of the provided eth
etho_ip            = " | awk '/inet addr/ {print $2}' | awk -F: '{print $NF}'";

# this will query the mask address for the given eth
mask_addr        = " | awk '/Mask:/ {print $0}' | awk -F: '{print $NF}'";

# this will query the mac address for the given eth
mac_addr        = " | awk '/HWaddr/ {print $0}' | awk -F' ' '{print $NF}'";

# ifconfig command to collect os info
ifconfig        = "ifconfig ";

#ILOM properties
# to collect ilom ipaddress
IlomIpAddress    = "sudo ipmitool lan print | awk -F: '/^IP Address/&&!/Source/ {print $2}'";

# to collect ilom mac address
IlomMacAddress    = "sudo ipmitool lan print | awk -F': ' '/^MAC Address/ {print $2}'";

# gateway
gateway        = "netstat -rn | awk '/UG/ {print $2}'";

# vendor
vendor        = "sudo dmidecode -s system-manufacturer";

# tag
tag         = "sudo dmidecode -s baseboard-asset-tag";

#Asset Attributes
# biostag
biostag         = "sudo dmidecode -s baseboard-asset-tag";

# kernelversion
kernelversion         = "uname -r";

# cores
cores = "cat /proc/cpuinfo | grep 'cpu cores'"

# hyperthread
corehypercount = "dmidecode -t processor | grep 'Core Count'"
threadhypercount = "dmidecode -t processor | grep 'Thread Count'"

totaldisk = "cat /proc/partitions | grep -w 'sda' | awk '/sda/ {print $3}'"

# initializing logging to a file and setting the level of logging
dLogger = logging.getLogger("module");

# initialize hash, these will be used to build the json structure
ec =0;
main_hash = {};
kv_hash_list = [];
asset_hash_list = [];
label_value_hash = {};
all_hash = {};
in_list = [];
in_hash = {};

# this method will execute a command and return its result
def execute_cmd(COMMAND):
    dLogger.debug("Here is the command to run %s", COMMAND);
    try:
        command_result = commands.getstatusoutput(COMMAND);
        dLogger.debug("Here is the result of the command %s", command_result[1]);
        return (command_result[0],command_result[1].strip());
    except:
        dLogger.debug("Failed to get value for command with returned error %s", command_result[0]);
        return (1, "Failed to get value for command " + COMMAND + " Returned Error: " + command_result[0]);

# this method will parse the output of the command
def parse_output(code,msg):
    dLogger.debug("Parsing the output code %s", code);
    dLogger.debug("Parsing the output message %s", msg);
    if(code != 0):
        ec =1;
        print_output();

# need to create a json structure like below:
# {"device": "ETH0", "mac": "00:26:6c:f9:d2:fc", "ipAddress": "10.18.184.202"}
def build_interfaces_hash(interface_name):
    my_hash = {};
    #device
    my_hash['device'] = interface_name.upper();
    #ipAddress
    eth_ipaddress_command  = ifconfig + interface_name + etho_ip;
    (ec,op) = execute_cmd(eth_ipaddress_command);
    parse_output(ec,op);
    my_hash['ipAddress'] = op;
    #mac
    eth_ipaddress_command  = ifconfig + interface_name + mac_addr;
    (ec,op) = execute_cmd(eth_ipaddress_command);
    parse_output(ec,op);
    my_hash['mac'] = op;

    return my_hash;

# This is for building ILom strcuture. it should look like:
# "ilomInterface": {"ipAddress": "10.18.184.200", "mac": "255.0.0.0"}
def build_ilom_hash(my_hash, interface_name):
    my_hash[interface_name]= {};
    #ipAddress
    ilom_ipaddress_command  = IlomIpAddress;
    (ec,op) = execute_cmd(ilom_ipaddress_command);
    parse_output(ec,op);
    my_hash[interface_name]['ipAddress'] = op;
    #mac
    ilom_mac_command  = IlomMacAddress;
    (ec,op) = execute_cmd(ilom_mac_command);
    parse_output(ec,op);
    my_hash[interface_name]['mac'] = op;

    return my_hash;

# this method builds the label/value list which is then wrapped in a hash by com.ebay.eskernel.LabelledValue
# we do this so os provision can just marshall this to a object which can be used to update the wiri info
def print_output():
    attr_hash = {};
    attr_hash['com.ebay.eskernel.LabelledValue'] = kv_hash_list;
    osdetail_hash = {};
    osdetail_hash['attributes'] = attr_hash;

    assets_attr_hash = {};
    assets_attr_hash['com.ebay.eskernel.LabelledValue'] = asset_hash_list;
    osdetail_hash['assetAttributes'] = assets_attr_hash;

    main_hash['osDetail'] = osdetail_hash;
    main_hash['interfaces'] = in_hash;

    response = '{"ExtendedAssetInfo":';
    response = response + json.dumps(main_hash);
    response = response + "}";
    dLogger.debug("Here is the final json string being returned %s", response);
    return response;

# build the list of label/values
def set_props(label, value):
    my_hash = {};
    my_hash['label'] = label;
    my_hash['value'] = value;
    kv_hash_list.append(my_hash);

# build the list of label/values for assets
def set_asset_props(label, value):
    my_hash = {};
    my_hash['label'] = label;
    my_hash['value'] = value;
    asset_hash_list.append(my_hash);


# all functions defined . now execute the commands

(ec,op) = execute_cmd(gateway);
parse_output(ec,op);
set_props("gateway", op);

(ec,op) = execute_cmd(ifconfig + "eth0" + mac_addr);
parse_output(ec,op);
set_props("physaddress", op);

(ec,op) = execute_cmd("date");
parse_output(ec,op);
set_props('scantime', op);

(ec,op) = execute_cmd(ifconfig + "eth0" + mask_addr);
parse_output(ec,op);
set_props('subnetmask', op);

(ec,op) = execute_cmd(vendor);
parse_output(ec,op);
set_props('vendor', op);

(ec,op) = execute_cmd(tag);
parse_output(ec,op);
set_props('tag', op);

(ec,op) = execute_cmd(hostname);
parse_output(ec,op);
set_props('hostname', op);

(ec,op) = execute_cmd(timezone);
parse_output(ec,op);
set_props('timezone', op);

(ec,op) = execute_cmd(auth);
parse_output(ec,op);
set_props('authentication', op);

(ec,op) = execute_cmd(ntp_status);
parse_output(ec,op);
set_props('ntpservice', op);

(ec,op) = execute_cmd(uname_sr);
parse_output(ec,op);
set_props('kernel', op);

(ec,op) = execute_cmd(model);
parse_output(ec,op);
set_props('model', op);

(ec,op) = execute_cmd(serial);
parse_output(ec,op);
set_props('serial', op);

(ec,op) = execute_cmd(cpu_count);
parse_output(ec,op);
set_props('cpucount', op);

(ec,op) = execute_cmd(ifconfig + "eth0" + etho_ip);
parse_output(ec,op);
set_props('ipaddress', op);

(ec,op) = execute_cmd(fqdn);
parse_output(ec,op);
set_props('fqdn', op);

(ec,op) = execute_cmd(label);
parse_output(ec,op);
set_props('label', op);

(ec,op) = execute_cmd(memory);
parse_output(ec,op);
set_props('memory', op);

(ec,op) = execute_cmd(uname_ms);
parse_output(ec,op);
set_props('ostype', op);

(ec,op) = execute_cmd(uuid);
parse_output(ec,op);
set_props('uuid', op);

# Collect all asset details
(ec,op) = execute_cmd(biostag);
parse_output(ec,op);
set_asset_props('biostag', op);

(ec,op) = execute_cmd(kernelversion);
parse_output(ec,op);
set_asset_props('kernelversion', op);

(ec,op) = execute_cmd(totaldisk);
parse_output(ec,op);
set_asset_props('totaldisk', op);

(ec,op) = execute_cmd(cpu_count);
parse_output(ec,op);
set_asset_props('cpucount', op);

(ec,op) = execute_cmd(memory);
parse_output(ec,op);
set_asset_props('memory', op);

(ec,op) = execute_cmd(uname_ms);
parse_output(ec,op);
set_asset_props('ostype', op);

(ec,op) = execute_cmd("date");
parse_output(ec,op);
set_props('scantime', op);
set_asset_props('scantime', op);


# Collect all active interfaces and get their requiret attributes.
all_interfaces = {};

(ec,op) = execute_cmd(ifconfig + interfaces);
parse_output(ec,op);
interface_names = op.splitlines();
for interface_name in interface_names:
    in_list.append(build_interfaces_hash(interface_name));

# need to put this label/value list hash in NetworkInterface so it can by marshalled into an os provisiong object
in_hash['com.ebay.cloud.ims.osprovisioning.beans.NetworkInterface'] = in_list;

# collect ilom info, ipaddress & mac
build_ilom_hash(main_hash, "ilomInterface");


(ec,op) = execute_cmd(dns);
parse_output(ec,op);
dnsservers = op.splitlines();
if len(dnsservers) > 1:
    set_props('primarydns', dnsservers[0]);
    set_props('secondarydns', dnsservers[1]);
else:
    set_props('primarydns', dnsservers);
    set_props('secondarydns', "Could not found. Check command on system");

(ec,op) = execute_cmd(ntp_drift);
parse_output(ec,op);
if(op > 0):
    set_props('ntpdrift', "y");
else:
    set_props('ntpdrift', "n");


(ec,op) = execute_cmd(lsb_release);
parse_output(ec,op);
model = "Could not found. Check command on system";
lsb_arr     = op.splitlines();
if len(lsb_arr) > 2:
    dis_id_str   = lsb_arr[0].split("=");
    dis_rel_str  = lsb_arr[1].split("=");
    dis_code_str = lsb_arr[2].split("=");
    if len(dis_id_str) > 0 & len(dis_rel_str) > 0 & len(dis_code_str) > 0:
        model = dis_id_str[1] + " " + dis_rel_str[1] + " " + dis_code_str[1];

set_props('osversion', model);


(ec,op) = execute_cmd(cores);
parse_output(ec,op);
lsb_arr     = op.splitlines();
cores_value = "Could not found. Check command on system";
if len(lsb_arr) > 0:
    core_str   = lsb_arr[0].split(":");
    if len(core_str) > 1:
        cores_value = core_str[1];

set_asset_props("cores",cores_value)

(ec,op) = execute_cmd(corehypercount);
parse_output(ec,op);
lsb_arr     = op.splitlines();
core_count = "Could not found. Check command on system";
if len(lsb_arr) > 0:
    core_count_str   = lsb_arr[0].split(":");
    if len(core_count_str) > 1:
        core_count = core_count_str[1];
        dLogger.debug("Core_count value %s", core_count);

(ec,op) = execute_cmd(threadhypercount);
parse_output(ec,op);
lsb_arr     = op.splitlines();
thread_count = "Could not found, Check command on system";
if len(lsb_arr) > 0:
    thread_count_str   = lsb_arr[0].split(":");
    if len(thread_count_str) > 1:
        thread_count = thread_count_str[1];
        dLogger.debug("Thread_count value %s", thread_count);

hyperthread = ''
if(core_count==thread_count):
    hyperthread = 'disabled'
else:
    hyperthread = 'enabled'

set_asset_props("threads",thread_count)
set_asset_props("hyperthread",hyperthread)


print_output();

