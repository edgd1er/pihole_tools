#!/usr/bin/env python3

"""
phadlist.py
- load a file given in args, add lists (-a) and remove (-r).
- set groups and comments if given.
  https://docs.pi-hole.net/api/
  https://ftl.pi-hole.net/master/docs/
"""

import argparse
import configparser
import json
import logging
import os.path
import re
import socket
import sys
import urllib
from typing import List

import requests
from requests import Request

# Variables
LDIR = os.path.dirname(os.path.realpath(__file__))
adlist = os.path.join(os.path.dirname(os.path.abspath(__file__)), "adlists.list")
loadedgroups = []
loadedlists = []
headers = {}
logger = None
logged = False
PHMARKER = '[phtool]'
APIURL = ""
APIPASSWORD = ""
try:
  script_name = os.path.basename(__file__)
except NameError:
  script_name = os.path.basename(sys.argv[0])
ini_file = f'{os.path.splitext(script_name)[0]}.ini'


# class
class OneList():
  def __init__(self, url: str, group: str = "default", comment: str = "None", type: str = 'block'):
    self.url: str = url
    self.group: List[str] = group.split(',')
    self.comment: str = comment
    self.groups_id: List[int] = []  # most of the time group id is not create when the file is loaded
    self.type: str = type if type in ['allow', 'block'] else 'block'

  def get_url(self):
    return f'{self.url}'

  def get_groups(self):
    return self.group

  def get_comment(self):
    return self.comment

  def get_groups_id(self):
    return self.groups_id

  def set_groups_id(self, group_id: List[int]):
    self.groups_id = group_id

  def get_type(self):
    return self.type


# TODO revoir type valeurs
class OneDomain():
  def __init__(self, domain: str = "", group: str = "default", comment: str = "None", type: str = 'deny'):
    self.domain: str = domain
    self.group: List[str] = group.split(',')
    self.comment: str = comment
    self.groups_id: List[int] = []  # most of the time group id is not create when the file is loaded
    self.type: str = type if type in ['allow', 'allow-regex', 'deny', 'deny-regex'] else 'deny'

  def get_domain(self):
    return f'{self.domain}'

  def get_groups(self):
    return self.group

  def get_comment(self):
    return self.comment

  def get_groups_id(self):
    return self.groups_id

  def set_groups_id(self, group_id: List[int]):
    self.groups_id = group_id

  def get_type(self):
    return self.type


# Functions
# generic query function
def getpostapi(apiconfig: {} = None, path: str = "", method: str = "get", payload: {} = None) -> json:
  """
  generic function to query api: https://ftl.pi-hole.net/master/docs/
  :param apiconfig:
  :param path:
  :param method: GET or POST
  :param headers: type and auth headers
  :param payload: json payload to send to the api
  :return: response json or text
  """
  url = f'https://{apiconfig.get("fqdn")}/api/{path}'
  data = {}

  r = Request(method=method, url=url, data=json.dumps(payload))
  prepped = apiconfig.get('session').prepare_request(r)
  logger.debug(f'method: {prepped.method}, url: {prepped.url}, headers: {prepped.headers}, data: {prepped.body}')
  try:
    resp = apiconfig.get('session').send(prepped, verify=apiconfig.get('verify'), timeout=apiconfig.get('timeout'))
  except Exception as e:
    logger.error(f'Request error: {e}')
    sys.exit(1)
  if resp.status_code in [400, 401, 404]:
    logger.error(f'status: {resp.status_code}, method: {method}, url: {url}, text: {resp.text}')
    return None
  if resp.status_code in [204]:
    if method == 'DELETE':
      if 'auth' in path:
        logger.info('python session disconnected from API')
      if 'lists/' in path:
        logger.info('list delete: {path}')
    if method == 'POST':
      logger.info(f'POST, status: {resp.status_code}, url: {url}')
    return {}
  if resp.status_code in [200, 201, 202, 204]:
    try:
      data = resp.json()
    except requests.JSONDecodeError:
      logger.error(f'not a json: {resp.text}, type: {r.headers.get("Content-type")}')
      if path == 'auth':
        sys.exit(-1)
  else:
    logger.error(f'RC: {resp.status_code}, url: {url}, content: {resp.text}')
    if path == 'auth':
      sys.exit(-1)

  logger.debug(f'json: {data}, url: {url}, txt:{resp.text}')
  return data


# function query the api
def get_session_token(apiconfig: {} = None, password: str = "") -> {}:
  payload = {"password": password}
  logger.debug(f'payload: {payload}')
  data = getpostapi(apiconfig=apiconfig, path='auth', method='post', payload=payload)

  logger.debug(f'json: {data}')
  if data is not None:
    apiconfig.get('session').headers.update({
      "accept": "application/json",
      "content-type": "application/json",
      "X-FTL-SID": f'{data['session']['sid']}',
      "X-FTL-CSRF": f'{data['session']['csrf']}'
    })
  else:
    logger.error(f'No session found: {data}')
    sys.exit(1)

  return headers


def close_session(apiconfig: {} = None, close_all: bool = False) -> {}:
  sessions = data = getpostapi(path='auth/sessions', method='get', apiconfig=apiconfig, payload={})
  logger.debug(f'active sessions: {sessions}')
  logger.info(f'active sessions before closing this one:{len(sessions['sessions'])}')
  c = 0
  if close_all:
    for s in sessions['sessions']:
      if s['current_session'] == False and 'python' in s['user_agent']:
        c += 1
        data = getpostapi(path=f'auth/session/{s["id"]}', method='delete', apiconfig=apiconfig)
        logger.debug(f'deleted session: {s["id"]}, agent: {s["user_agent"]}, data: {data}')

  data = getpostapi(path='auth', method='delete', apiconfig=apiconfig)
  logger.debug(f'json: {data}')
  logger.info(f'Closed sessions: {c + 1}')


def get_version(apiconfig: {} = None) -> {}:
  version = getpostapi(path='info/version', method='get', apiconfig=apiconfig)
  logger.debug(f'type: {type(version)}, json: {version}')
  return version


# Lists
def get_lists(apiconfig: {} = None) -> {}:
  data = getpostapi(path='lists', apiconfig=apiconfig, method='GET')
  lists = data['lists']
  took = data['took']
  logger.debug(f'# of lists: {len(lists)}, took: {took}')
  return lists


def add_lists(apiconfig: {} = None, list: OneList = None, replace: bool = False) -> any:
  payload = {'address': list.get_url(), 'type': list.get_type(), 'groups': list.get_groups_id(),
             'comment': list.get_comment(),
             'enabled': True}
  if replace:
    logger.debug(f'Replacing list: {payload}')
    data = getpostapi(path='lists', method='PUT', apiconfig=apiconfig, payload=payload)
  else:
    logger.debug(f'adding list: {payload}')
    data = getpostapi(path='lists', method='POST', apiconfig=apiconfig, payload=payload)
  logger.debug(f'json: {data}')
  return data


def remove_lists(type: str = 'phtool', apiconfig: {} = None) -> {}:
  apilists = get_lists(apiconfig=apiconfig)
  todelete = None
  if len(apilists) == 0:
    logger.warning(f'No lists to delete.')
    return

  if type == 'mine':
    todelete = list(filter(lambda x: x['comment'].__contains__(PHMARKER), apilists))
  if type == 'all':
    todelete = apilists['lists']
  if type == 'reset':
    todelete = list(filter(lambda x: x['comment'] not in 'Pi-hole defaults', apilists))

  logger.debug(f'requested: {type}, # to delete: {len(todelete)} lists to delete: {todelete}')
  logger.info(f'requested: {type}, # to delete: {len(todelete)}')
  c = 0
  items = []
  for l in todelete:
    payload = {'item': l['address'], 'type': l['type']}
    items.append(payload)
    c += 1
  if len(items) > 0:
    data = getpostapi(path=f'lists:batchDelete', method='POST', apiconfig=apiconfig, payload=items)
    if data is None:
      logger.warning(f'not deleted list: {list(map(lambda x: x["address"], items))}')
      c = 0

  logger.info(f'{c}/{len(todelete)} deleted.')


# Domains
def get_domains(apiconfig: {} = None) -> {}:
  data = getpostapi(path='domains', apiconfig=apiconfig, method='GET')
  domains = data['domains']
  took = data['took']
  logger.debug(f'# of domains: {len(domains)}, took: {took}')
  return domains


def get_type_kind(typekind: str = 'deny-exact') -> (str, str):
  tmp = typekind.split('-', maxsplit=1)
  type = tmp[0]
  if len(tmp) == 1:
    kind = 'exact'
  else:
    kind = tmp[1] if tmp[1] == 'regex' else 'exact'
  return type, kind


def add_domains(apiconfig: {} = None, domain: OneDomain = None, replace: bool = False) -> any:
  type, kind = get_type_kind(domain.get_type())
  payload = {'domain': domain.get_domain(), 'groups': domain.get_groups_id(),
             'comment': domain.get_comment(), 'enabled': True}
  if replace:
    logger.debug(f'Replacing domain: {payload}')
    data = getpostapi(path=f'domains/{type}/{kind}', method='PUT', apiconfig=apiconfig, payload=payload)
  else:
    logger.debug(fr'adding domain: {payload}')
    data = getpostapi(path=f'domains/{type}/{kind}', method='POST', apiconfig=apiconfig, payload=payload)
  logger.debug(fr'#errors: {len(data["processed"]["errors"])}, processed: {data['processed']}')

  if len(data['processed']['errors']) > 0:
    errorlist = " ".join([f'{e["item"]}: {e["error"]}' for e in data['processed']['errors']])
    logger.error(f'error while adding domain: {errorlist}')
  if len(data['processed']['success']) > 0:
    successlist = " ".join([f'{e["item"]}' for e in data['processed']['success']])
    logger.info(fr'added domain:{successlist}')

  return data


def remove_domains(type: str = 'phtool', apiconfig: {} = None) -> {}:
  apidomains = get_domains(apiconfig=apiconfig)
  todelete = list()
  if len(apidomains) == 0:
    logger.warning(f'No lists to delete.')
    return

  # logger.debug(f'apidomains: {apidomains}')
  if type == 'mine':
    for d in apidomains:
      if d['comment'] is not None and d['comment'].__contains__(PHMARKER):
        todelete.append(d)
        logger.debug(fr'url: {d['domain']}, comment: {d["comment"]}')
    logger.debug(fr'todelete: {todelete}')
  if type == 'all':
    todelete = apidomains

  logger.debug(f'requested: {type}, # to delete: {len(todelete)} lists to delete: {todelete}')
  logger.info(f'requested: {type}, # to delete: {len(todelete)}')
  c = 0
  items = []
  for l in todelete:
    payload = {'item': l['domain'], 'type': l['type'], 'kind': l['kind']}
    items.append(payload)
    c += 1
  if len(items) > 0:
    data = getpostapi(path=f'domains:batchDelete', method='POST', apiconfig=apiconfig, payload=items)
    if data is None:
      logger.warning(f'not deleted list: {list(map(lambda x: x["address"], items))}')
      c = 0
  else:
    logger.warning(f'Nothing to delete with type {type}')
    logger.debug(f'todelete: {todelete}')

  logger.info(f'{c}/{len(todelete)} deleted.')


# groups
def get_groups(apiconfig: {} = None) -> {}:
  groups = getpostapi(path='groups/', apiconfig=apiconfig)
  logger.debug(f'groups: {groups}')
  ngroups = dict(map(lambda g: (g['name'], g['id']), groups['groups']))
  logger.debug(f'ngroups: {ngroups}')
  return ngroups


def add_groups(groups: List[str] = None, apiconfig: {} = None) -> {}:
  if groups == None:
    logger.warning('No group given. Exiting')
    return
  payload = {'name': groups, 'comment': f'{" ".join(groups)} [ph5lt]', 'enabled': True}
  r = getpostapi(path='groups', method='POST', apiconfig=apiconfig, payload=payload)
  logger.debug(f'json: {r}')
  if r['processed'] == 'null':
    logger.error(f'Error while adding group: {r}')
  for e in r['processed']['errors']:
    logger.error(f'Error while adding group: {e["item"]}, {e["error"]}')
  return r


def remove_groups(apiconfig: {} = None, group: str = ""):
  if group == "":
    logger.warning('No group given. Exiting')
    return
  payload = {}
  r = getpostapi(path=f'groups/{group}', method='DELETE', apiconfig=apiconfig, payload=payload)
  logger.debug(f'status: {r.status_code},text: {r.text} ')
  return r


########################################################################################
def show_version(version: {} = None):
  if version == None:
    logger.warning('No version given. Exiting')
  # logger.debug(f'version: {version}')
  logger.info(
    f'version: docker {version["version"]["docker"]["local"]}, core: {version["version"]["core"]["local"]["version"]}/{version["version"]["core"]["remote"]["version"]}\
  , web: {version["version"]["web"]["local"]["version"]}/{version["version"]["web"]["remote"]["version"]}\
  , ftl: {version["version"]["ftl"]["local"]["version"]}/{version["version"]["ftl"]["remote"]["version"]}')


def checkFile(filename: str = ''):
  if filename is None:
    logger.error(f'No file given. Exiting')
    sys.exit(-1)
  if not os.path.isfile(filename):
    logger.error(f'file not found ({filename}). Exiting')
    sys.exit(-1)


def load_domain(filename: str = None) -> List[OneDomain]:
  domains = []
  checkFile(filename)

  logger.debug(f'Loading file: {filename}')
  with open(filename, mode="+r") as f:
    lines = f.readlines()

  if len(lines) < 1:
    logger.error(f'No file read: {filename}')

  comment = 'No comment'
  i = 0
  a = 0
  for line in lines:
    i += 1
    # split on spaces
    tmp = line.strip('\n').split('#', maxsplit=1)
    logger.debug(fr'len: {len(tmp)}, tmp: {tmp}, comment: {comment}, line: {line}')

    domain = ''
    type = 'deny'
    group = 'Default'
    # line start with #
    if tmp[0] == '':
      comment = line
      payload = []
    else:
      payload = tmp[0].split(None)
      comment = tmp[1] if len(tmp) > 1 else comment
      domain = str(payload[0])
      # No group given, assigning to Default
      if len(payload) > 1:
        group = payload[1]
      # get comment
      if len(payload) >= 2:
        # type given, get it.
        if payload[1] in ('deny', 'allow', 'deny-regex', 'allow-regex'):
          type = payload[1]
          group = payload[2] if len(payload) >= 3 else group
        else:
          # No type, so next one is group
          group = payload[1]

    logger.debug(fr'len: {len(payload)}, payload: {payload}, comment: {comment}, line: {line}')
    if domain != '' and domain not in [ll.get_domain() for ll in domains]:
      logger.debug(fr'loaded domain: {domain}, type: {type}, group: {group}, comment: {comment}')
      l = OneDomain(domain=domain, type=type, group=group, comment=f'{PHMARKER} {comment}')
      # add object if domain is not found and not empty
      a += 1
      domains.append(l)
    else:
      logger.warning(f'domain ({domain}) already present or empty.')

  logger.info(f'found {len(domains)} unique domains out of {a} lines in {os.path.basename(filename)}.')
  return domains


def load_list(filename: str = None) -> List[OneList]:
  lists = []
  checkFile(filename)
  logger.debug(f'Loading file: {filename}')
  with open(filename, mode="+r") as f:
    lines = f.readlines()

  if len(lines) < 1:
    logger.error(f'No file read: {filename}')

  comment = 'No comment'
  i = 0
  a = 0
  for line in lines:
    i += 1
    # split on spaces
    tmp = line.strip('\n').split('#', maxsplit=1)
    logger.debug(f'len: {len(tmp)}, payload: {tmp}, comment: {comment}, line: {line}')

    url = ''
    type = 'block'
    group = 'Default'
    # line start with #
    if tmp[0] == '':
      comment = line
      payload = []
    else:
      payload = tmp[0].split(None)
      comment = tmp[1] if len(tmp) > 1 else comment
      url = payload[0]
      # No group given, assigning to Default
      if len(payload) >= 1:
        group = payload[1]
      # get comment
      if len(payload) >= 2:
        # type given, get it.
        if payload[1] in ('block', 'allow'):
          type = payload[1]
          group = payload[2] if len(payload) >= 3 else group
        else:
          # No type, so next one is group
          group = payload[1]

    logger.debug(f'len: {len(payload)}, payload: {payload}, comment: {comment}, line: {line}')
    if url != '' and url not in [ll.get_url() for ll in lists]:
      logger.debug(f'adding list: {url}, type: {type}, group: {group}, comment: {comment}')
      l = OneList(url=url, type=type, group=group, comment=f'{PHMARKER} {comment}')
      # add object if not url is not found
      a += 1
      lists.append(l)
    else:
      logger.warning(f'url ({url}) already present or empty.')

  logger.info(f'found {len(lists)} unique lists out of {i} lines in {os.path.basename(filename)}.')
  return lists


def get_list_of_groups_from_loaded_list(loaded_list):
  loaded_groups = set()
  for l in loaded_list:
    for g in l.get_groups():
      loaded_groups.add(g)
  logger.debug(f'loaded_groups: {loaded_groups}')
  return list(loaded_groups)


def process_lists(apiconfig: {} = None, api_groups=None, filename: str = None, replace: bool = False) -> {}:
  loaded_list = load_list(filename)
  loaded_groups = get_list_of_groups_from_loaded_list(loaded_list)

  # get array of existing groups.
  logger.debug(f'loaded_groups: {loaded_groups}')
  logger.debug(f'api groups: {api_groups}')
  newgroups = []
  # create a list of not existing groups
  for l in loaded_groups:
    if l not in api_groups.keys():
      newgroups.append(l)
      logger.debug(f'new group: {l}')
  logger.debug(f'new groups: {len(newgroups)}, {newgroups}')
  # create missing groups
  if len(newgroups) != 0:
    r = add_groups(apiconfig=apiconfig, groups=newgroups)
    logger.debug(f'add groups result: {r}')
    # fetch new api groups
    api_groups = get_groups(apiconfig=apiconfig)

  # check for new lists
  apilists = get_lists(apiconfig=apiconfig)
  adresses = list(map(lambda x: x['address'], apilists))
  newlists = list()
  for l in loaded_list:
    if l.get_url() not in adresses:
      # New url found, need to add group ids:
      gid = []
      for g in l.get_groups():
        gid.append(api_groups.get(g))
      l.set_groups_id(gid)
      logger.debug(f'list to add: {l.get_url()}, {l.get_groups()}/{l.get_groups_id()}, {l.get_comment()}')
      newlists.append(l)
      r = add_lists(apiconfig=apiconfig, list=l, replace=replace, type='block')
      logger.debug(f'addList result: {r}')
      logger.info(f'addlist result: id: {r["lists"][0]["id"]}, address: {r["lists"][0]["address"]}')

  logger.info(f'# of newLists to add: {len(newlists)}')


def process_domains(apiconfig: {} = None, api_groups=None, filename: str = None, replace: bool = False) -> {}:
  loaded_domains = load_domain(filename)
  logger.debug(fr'loaded_domains: {[d.get_domain() for d in loaded_domains]}')
  loaded_groups = get_list_of_groups_from_loaded_list(loaded_domains)

  # get array of existing groups.
  logger.debug(f'loaded_groups: {loaded_groups}')
  logger.debug(f'api groups: {api_groups}')
  newgroups = []
  # create a list of not existing groups
  for d in loaded_groups:
    if d not in api_groups.keys():
      newgroups.append(d)
      logger.debug(f'new group: {d}')
  logger.debug(f'new groups: {len(newgroups)}, {newgroups}')
  # create missing groups
  if len(newgroups) != 0:
    r = add_groups(apiconfig=apiconfig, groups=newgroups)
    logger.debug(f'add groups result: {r}')
    # fetch new api groups
    api_groups = get_groups(apiconfig=apiconfig)

  # check for new lists
  apidomains = get_domains(apiconfig=apiconfig)
  newdomains = list()
  logger.debug(f'api domains: {apidomains}')

  # parse domains loaded from file.
  for d in loaded_domains:
    found = False
    # search in pihole domains and compare domain, type & kind
    for a in apidomains:
      if a['domain'] == d.get_domain():
        type, kind = get_type_kind(d.get_type())
        found = type == a['type'] and kind == a['kind']
        break
    if not found:
      logger.debug(fr'domain {d.get_domain()} not found, type:{d.get_type()}, found: {found}')
      # New url found, need to add group ids:
      gid = []
      for g in d.get_groups():
        gid.append(api_groups.get(g))
      d.set_groups_id(gid)
      logger.debug(fr'list to add: {d.get_domain()}, {d.get_groups()}/{d.get_groups_id()}, {d.get_comment()}')
      newdomains.append(d)
      r = add_domains(apiconfig=apiconfig, domain=d, replace=replace)

  logger.info(f'# of new Domains to add: {len(newdomains)}')


def read_instance(config: configparser.ConfigParser, instance: str):
  logger.debug(f'instance: {instance}, config: {config.sections()}')
  if instance in config.sections():  # checks if the given instance actually exists in the config file
    # read the specific config data and then convert it into an integer
    api_url = config.get(section=instance, option='api_url', fallback='http://pihole.net/')
    api_password = config.get(section=instance, option='api_password', fallback='this_is_a_password')
    logger.debug(f'api_url: {api_url}, api_password: {api_password}')
    return api_url, api_password
  else:
    logger.error(f'no section found, returning default values')
    return "http://pihole.net", "password"


# Main
def main():
  log_dir = f'{LDIR}/logs'
  # argParser
  parser = argparse.ArgumentParser(description='manage lists and domains through pihole API')
  parser.add_argument('-l', '--lists', action='store_true', help='load lists found in <file>')
  parser.add_argument('-L', '--remove_lists', choices=['all', 'mine', 'reset'], help='remove lists: all, mine, reset')
  parser.add_argument('-d', '--domains', action='store_true', help='load domain found in <file>')
  parser.add_argument('-D', '--remove_domains', choices=['all', 'mine'],
                      help='remove domains: all, mine, reset')
  parser.add_argument('-c', '--conf', help='read config <file>,load <param> section')
  parser.add_argument('-f', '--file', action='store', help='load from file')
  parser.add_argument('-r', '--replace', action='store_true', help='replace if possible groups and lists')

  parser.add_argument('-q', '--quiet', action='store_true', help='if set to true, output error only')
  parser.add_argument('-m', '--mail', action='store_true', help='send mail even when not run by cron')
  parser.add_argument('-s', '--stats', action='store_true', help='send mail with statistics')
  parser.add_argument('-v', '--verbose', action='store_true', help='More output.')

  # parser
  args = parser.parse_args()
  log_level = logging.INFO
  if args.verbose:
    log_level = logging.DEBUG
  if args.quiet:
    log_level = logging.ERROR
  logger.setLevel(log_level)

  current_svr = socket.gethostname()
  if args.conf:
    current_svr = args.conf

  s = requests.session()
  (APIURL, APIPASSWORD) = read_instance(config, current_svr)
  apiconfig = {'session': s, 'fqdn': APIURL, 'timeout': 5, 'verify': True}
  headers = get_session_token(apiconfig=apiconfig, password=APIPASSWORD)
  if headers == None:
    logger.error(f'no session token found')
    sys.exit(1)

  logged = True
  show_version(get_version(apiconfig=apiconfig))
  groups = get_groups(apiconfig=apiconfig)

  if args.lists:
    process_lists(apiconfig=apiconfig, api_groups=groups, filename=args.file, replace=args.replace)
  if args.remove_lists:
    remove_lists(apiconfig=apiconfig, type=args.remove)

  if args.domains:
    process_domains(apiconfig=apiconfig, api_groups=groups, filename=args.file, replace=args.replace)

  if args.remove_domains:
    remove_domains(apiconfig=apiconfig, type=args.remove_domains)

  if logged:
    data = close_session(apiconfig=apiconfig, close_all=True)


if __name__ == "__main__":
  logging.basicConfig(format='%(asctime)s;%(levelname)s:%(name)s:%(funcName)s - %(lineno)s:%(message)s',
                      level=logging.INFO)
  logger = logging.getLogger(__name__)
  ## mail setings
  smtp = {
    'from': f'{os.uname().nodename.split(".")[0]}@mission.lan',
    'to': 'holdom3@mission.lan',
    'server': 'postfixlb2.mission.lan',
    'port': '465',
    'username': 'h3user',
    'password': 'h3password'}

  logger.setLevel(logging.DEBUG)
  # config read
  current_svr = socket.gethostname()
  config = configparser.ConfigParser()
  ini_file_full = f'{LDIR}{os.sep}{ini_file}'
  if not os.path.exists(ini_file_full):
    logger.error(f'ini file not found: {ini_file_full}')
    sys.exit(1)
  logger.info(f'Read: {ini_file_full}')
  config.read(filenames=f'{ini_file_full}')

  main()
  myhost = socket.gethostname()
