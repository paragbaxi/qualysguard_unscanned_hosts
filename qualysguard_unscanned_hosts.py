from __future__ import print_function
import argparse
import datetime
from collections import defaultdict
import logging, sys
import netaddr
import os
import qualysapi
from lxml import etree

def download_paginated(call, param, tag):
    """Download multiple pages of XML.
    """
    global qgc
    # Start with first host, which starts at 1.
    param['id_min'] = 1
    ips = netaddr.IPSet()
    # Start downloading all.
    id_min = 1
    while True:
        print('Downloading hosts from ID %d' % id_min)
        xml = qgc.request(call, param)
        # Parse.
        tree = etree.fromstring(xml)
        # Iterate through each host.
        elems = tree.findall('.//%s' % tag)
        for host in elems:
            ips.add(host.xpath('IP')[0].text)
        # Set up next request, if applicable.
        try:
            url = tree.xpath('/HOST_LIST_OUTPUT/RESPONSE/WARNING/URL')[0].text
            start = url.find('id_min') + 7
            end = url.find('&',start)
            id_min = int(url[start:end])
        except IndexError, e:
            # No next url. All hosts downloaded.
            break
    return ips

def ips_in_ip_list(xml):
    """Return set of extracted IPs from IP list XML.
    """
    tree = etree.fromstring(xml)
    ips = netaddr.IPSet()
    # Grab all IPs and IP ranges.
    ip_list = tree.xpath('//IP_SET/descendant::*/text()')
    for i in ip_list:
        print i
        if '-' in i:
            ip_start = i[:i.find('-')]
            ip_end = i[i.find('-')+1:]
            # ip_range += list(netaddr.iter_iprange(ip_start, ip_end))
            ips.add(netaddr.IPRange(ip_start,ip_end))
        else:
            ips.add(i)
    return ips

#
#  Begin
#
# Declare the command line flags/options we want to allow.
parser = argparse.ArgumentParser(description = 'What QualysGuard hosts have I not scanned?')
parser.add_argument('-t', '--truncation_limit',
                    default=1000,
                    help = 'How many hosts to download per call. (Default = 1000')
parser.add_argument('-v', '--verbose',
                    action = 'store_true',
                    help = 'Outputs additional information to log.')
parser.add_argument('--config',
                    help = 'Configuration for Qualys connector.')
# Parse arguments.
c_args = parser.parse_args()# Create log directory.
# Create log directory.
PATH_LOG = 'log'
if not os.path.exists(PATH_LOG):
    os.makedirs(PATH_LOG)
# Set log options.
LOG_FILENAME = '%s/%s-%s.log' % (PATH_LOG,
                                __file__,
                                datetime.datetime.now().strftime('%Y-%m-%d.%H-%M-%S'))
# Make a global logging object.
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
# This handler writes everything to a file.
logger_file = logging.FileHandler(LOG_FILENAME)
logger_file.setFormatter(logging.Formatter("%(asctime)s %(name)-12s %(levelname)s %(funcName)s %(lineno)d %(message)s"))
logger_file.setLevel(logging.INFO)
if c_args.verbose:
    logger_file.setLevel(logging.DEBUG)
logger.addHandler(logger_file)
# This handler prints to screen.
logger_console = logging.StreamHandler(sys.stdout)
logger_console.setLevel(logging.ERROR)
logger.addHandler(logger_console)
# Connect to QualysGuard API.
if c_args.config:
    qgc = qualysapi.connect(c_args.config)
else:
    qgc = qualysapi.connect()
# Find scanned IPs.
subscribed_ips = download_paginated('/api/2.0/fo/asset/host/',
                                    {'action': 'list', 'truncation_limit': c_args.truncation_limit},
                                    'HOST')
logger.debug('subscribed_ips = \n%s' % str(subscribed_ips))
# Find VM subscribed IPs.
scanned_vm_ips_xml = qgc.request('/api/2.0/fo/asset/host/',
                         {'action': 'list', 'compliance_enabled': '0'})
scanned_vm_ips = ips_in_ip_list(scanned_vm_ips_xml)
logger.debug('scanned_vm_ips = \n%s' % str(scanned_vm_ips))
# Print to file VM IPs not scanned but subscribed.
vm_unscanned = subscribed_ips.remove(scanned_vm_ips)
with open('vm_unscanned.txt', 'w') as f:
    for ip in vm_unscanned:
        print(ip, file=f)
# Find PC subscribed IPs.
scanned_pc_ips_xml = qgc.request('/api/2.0/fo/asset/host/',
                         {'action': 'list', 'compliance_enabled': '1'})
scanned_pc_ips = ips_in_ip_list(scanned_pc_ips_xml)
logger.debug('scanned_pc_ips = \n%s' % str(scanned_pc_ips))
# Print to file PC IPs not scanned but subscribed.
pc_unscanned = subscribed_ips.remove(scanned_pc_ips)
with open('pc_unscanned.txt', 'w') as f:
    for ip in pc_unscanned:
        print(ip, file=f)
exit()
