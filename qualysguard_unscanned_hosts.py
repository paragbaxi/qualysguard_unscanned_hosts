import argparse
import datetime
from collections import defaultdict
import logging
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
    ips = set()
    # Start downloading of all.
    while True:
        print 'Downloading hosts from ID %d' % id_min
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
    """Extract IPs from IP list.
    """
    tree = etree.fromstring(xml)
    ip_range = []
    # Grab all IPs and IP ranges.
    ip_list = tree.xpath('//IP_SET/descendant::*/text()')
    for i in ip_list:
        if '-' in i:
            ip_start = i[:i.find('-')]
            ip_end = i[i.find('-')+1:]
            ip_range += list(netaddr.iter_iprange(ip_start, ip_end))
    else:
        ip_range.append(i)

#
#  Begin
#
# Declare the command line flags/options we want to allow.
parser = argparse.ArgumentParser(description = 'What QualysGuard hosts have I not scanned?')
parser.add_argument('-t', '--truncation_limit',
                    default=1000,
                    help = 'How many hosts to download per call. (Default = 1000')
parser.add_argument('-v', '--debug',
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
# Find VM subscribed IPs.
vm_ips_xml = qgc.request('/api/2.0/fo/asset/host/',
    {'action': 'list', 'compliance_enabled', '0'})
vm_ips = ips_in_ip_list(vm_ips_xml)
tree.xpath('//IP_SET/descendant::*/text()')
# Find PC subscribed IPs.
pc_ips_xml = qgc.request('/api/2.0/fo/asset/host/',
    {'action': 'list', 'compliance_enabled', '1'})
pc_ips = ips_in_ip_list(pc_ips_xml)

exit()
