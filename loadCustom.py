#!/usr/bin/env python3

"""
loadCustom.py
- load custom.list (-c) and write (-w) to a file or (-r) to pihole.toml on remote hosts.
- ping (-p) hosts from custom.list.

apt install -y python3-tomlkit
./loadCustom.py -crw #load custom update pihole.toml and save it
./loadCustom.py -c localhost -v #resolve hosts with given dns server listed in custom.list and compare ip
"""

import argparse
import logging
import os.path
import socket
import subprocess
import sys
from collections import Counter
from pathlib import Path

import dns.resolver

try:
  import tomlkit
except ModuleNotFoundError:
  print('apt-get install -y python3-tomlkit')
  quit
from tomlkit.toml_file import TOMLFile

try:
  import tomllib
except ModuleNotFoundError:
  try:
    import tomli as tomllib
  except ModuleNotFoundError:
    print('pip3 install tomli')
    quit

# Variables
customlist = os.path.join(os.path.dirname(os.path.abspath(__file__)), "custom.list")


# Functions
def replace_or_add_host(custom_line: str, pihole_ip_hosts_l: list, pihole_ips_l) -> (list, list):
  """
  check if line exists in hosts list, if not add ip host or replace host
  if ip does not exist in pihole config, add it or replace the host if ip exists
  :param sline: ip host(s) to search in custom hosts list.
  """
  log.debug(f' #pihole_ip_hosts_l: {len(pihole_ip_hosts_l)}, #pihole_ips_l: {len(pihole_ips_l)}')

  # same line not found
  if custom_line not in pihole_ip_hosts_l:
    custom_ip = custom_line.split(" ")[0].strip()
    # log.debug(f' {custom_line } not in {pihole_ip_hosts_l}')
    # check if ip is not in ips list
    if custom_ip in pihole_ips_l:
      pihole_line = [x for x in pihole_ip_hosts_l if x.split(" ")[0].strip() == custom_ip]
      log.debug(f'existing ip: {custom_ip} found in {pihole_ips_l}')
      log.debug(f'removed {pihole_line}')
      pihole_ip_hosts_l.remove(pihole_line[0])
      pihole_ip_hosts_l.append(f'{custom_line}')
      log.debug(f'added {custom_line}')
      log.info(f'removed {" ".join(pihole_line)}, added {custom_line}')
    else:
      pihole_ips_l.append(custom_ip)
      pihole_ip_hosts_l.append(f'{custom_line} added')
      log.info(f'no match for {custom_line}, adding it.')
      log.debug(f'line: {" ".join(custom_ip)} not found in {" ".join(pihole_ips_l)}')

  # update document
  pihole_ips_l = list(map(lambda x: (x.split(" ")[0].strip()), pihole_ip_hosts_l))
  return pihole_ip_hosts_l, pihole_ips_l


def process_hosts():
  # get hosts from pihole.toml
  pihole_ip_hosts_l = pihole_config["dns"].get("hosts")
  pihole_ips_l = list(map(lambda x: (x.split(" ")[0].strip()), pihole_ip_hosts_l))
  log.debug(f'pihole_ips_l: {pihole_ips_l}')

  # Extract ip host from file.
  with open(f'{customlist}') as f:
    custom_hosts = list(filter(lambda x: (not x.startswith("#") and len(x) > 5), f.read().splitlines()))
  log.info(f'loaded {len(pihole_ips_l)} pihole ip from {piholetoml}, {len(custom_hosts)} custom ip from {customlist}')

  # parse custom.list
  for line in custom_hosts:
    # log.debug(f'searching {line}')
    custom_line = line.strip()
    (pihole_ip_hosts_l, pihole_ips_l) = replace_or_add_host(custom_line, pihole_ip_hosts_l, pihole_ips_l)

  c = Counter(pihole_ips_l)
  for i in pihole_ips_l:
    log.debug(f'{i} occured {c[i]} times')
    if c[i] > 1:
      log.error(f'Multiple value: {i} occured {c[i]} times')
  pihole_config["dns"]["hosts"] = sorted(pihole_ip_hosts_l)
  for l in pihole_config["dns"]["hosts"]:
    log.debug(f'HOST: {l}')


def getetcdir(ymldir: str):
  respath = subprocess.run([f'grep -o1P "([a-zA-Z0-9/_\\.]*)(?<=etc)/?:" {ymldir}/compose.yml | sed "s/://g"'],
                           capture_output=True, text=True, shell=True)
  log.debug(f'searching in {ymldir}: {respath.stdout}')
  if respath is None:
    log.error('Error when getting etc directory from /root/containers_conf/pihole/compose.yml')
    return "."

  log.debug(f'etc directory from /root/containers_conf/pihole/compose.yml: {respath.stdout}')
  return respath.stdout.rstrip()


def resolveHosts(nameserver: str = "127.0.0.1", port: int = 53, qType: str = "A"):
  '''
  ping hosts found in custom.list
  :return:
  '''
  with open(f'{customlist}') as f:
    custom_lines = list(filter(lambda x: (not x.startswith("#") and len(x) > 5), f.read().splitlines()))

  ip_errors = 0
  ip_ok = 0
  # prepare local dns as resolver
  #resolver = dns.resolver.make_resolver_at(where=nameserver, port=port)
  resolver = dns.resolver.Resolver()
  resolver.nameservers=[nameserver]
  resolver.port = port
  log.info(f'resolver: {" ".join(str(h) for h in resolver.nameservers)}:{resolver.port} - {namesvr}:{port}, loaded {len(custom_lines)} custom ip from {customlist}')

# parse custom.list
  for line in custom_lines:
    # log.debug(f'line: {line}')
    custom_ip = line.split(" ")[0].strip()
    custom_hosts = (line.replace("  ", " ")).split(" ")[1:]
    custom_hosts_filtered = list(filter(lambda x: len(x) > 0, custom_hosts))

    log.debug(f'hosts: {custom_hosts_filtered}')
    for idx, h in enumerate(custom_hosts_filtered):
      if (h.strip()) == "" or ((port == 553 and "mission.lan" not in h.strip() )):
        log.warning(f'{h.strip()} is not an mission.lan')
        continue
      try:
        tempIp = resolver.resolve(h, qType)
        #log.debug(f'tempIp: {tempIp}, rrset: {tempIp.rrset}')
        ip = tempIp.rrset[0].__str__()
        #log.info(f'{h} / {custom_ip} ?= {tempIp.response.answer[0][0]}')
        log.debug(f'{ip_errors + ip_ok:2} {idx:2}: {h} / {custom_ip} ?= {ip}')
        # log.debug(f'resolve: {tempIp.response.answer}, rrset: {tempIp.response}')
        if custom_ip != ip:
          log.error(f'{h.strip()} is not {custom_ip}, but got {ip}')
          ip_errors += 1
        else:
          ip_ok += 1
      # except socket.gaierror:
      except dns.resolver.NoAnswer as e:
        log.error(f'{h.strip()} is not {custom_ip}, but got {tempIp}. {e}')
        ip_errors += 1
      except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout ) as e:
        ip_errors+=1
        log.error(f'{h.strip()}: {e}')
  log.info(f'Ping results: resolver: {socket.gethostbyaddr(nameserver)[0]}:{port}, ok {ip_ok}, ko {ip_errors}')


# Main
if __name__ == "__main__":
  # setup logger
  logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                      format='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s - L%(lineno)s: %(message)s')
  global log, pihole_config, piholetoml
  log = logging.getLogger(__name__)

  # read pihole config.
  if socket.gethostname().split('.', 1)[0] in ("phoebe"):
    ymldir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "etc/")
  else:
    ymldir = getetcdir("/root/containers_conf/pihole/")

  piholetoml = os.path.join(f'{ymldir}', 'pihole.toml')

  # argParser
  parser = argparse.ArgumentParser(description='merge custom list into pihole.toml')
  parser.add_argument('-c', '--custom', action='store_true', help='load custom.list and update hosts array.')
  parser.add_argument('-C', '--check', action='extend', nargs="+", metavar="server:port",help='resolve hosts from custom.list and compare ip')
  parser.add_argument('-q', '--quiet', action='store_true', help='if set to true, output error only')
  parser.add_argument('-r', '--replace', action='store_true',
                      help='if set to true, save to same file, otherwise save as basename_new.tom file')
  parser.add_argument('-v', '--verbose', action='store_true', help='More output.')
  parser.add_argument('-w', '--write', action='store_true', help='save modified file')

  args = parser.parse_args()
  log_level = logging.INFO
  if args.verbose:
    log_level = logging.DEBUG
  if args.quiet:
    log_level = logging.ERROR
  log.setLevel(log_level)
  # logging.getLogger("urllib3").setLevel(logging.ERROR)

  if args.custom:
    if not os.path.exists(piholetoml):
      log.error(f'{piholetoml} does not exists')
      quit()
    piholebase = Path(piholetoml).stem
    log.debug(f'Reading {Path(piholetoml)}')
    pihole_string = Path(piholetoml).read_text(encoding="utf-8")
    pihole_config = tomlkit.loads(pihole_string)
    process_hosts()

  if args.write:
    if args.replace:
      sfile = piholetoml
      action = "Replacing data in"
    else:
      sfile = f'{piholebase}_new.toml'
      action = "Writing data in"
    tomlfile = TOMLFile(Path(sfile))
    tomlfile.write(pihole_config)
    log.info(f'{action} {sfile}')

  if args.check:
    current_host = socket.gethostname()
    log.debug(f'host: {current_host}, ping args: {args.check}')
    for h in args.check:
      host2process = h.split(':')[0] if h.__contains__(':') else h
      port2process = h.split(':')[1] if h.__contains__(':') else 53
      log.debug(f'{host2process}:{port2process}')
      namesvr = socket.gethostbyname(host2process)
      resolveHosts(nameserver=namesvr, port=port2process, qType="A")
