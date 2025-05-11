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
import socket
import sys
from typing import List

import requests
from requests import Request

# Variables
logger = logging.getLogger(__name__)
LDIR = os.path.dirname(os.path.realpath(__file__))
adlist = os.path.join(os.path.dirname(os.path.abspath(__file__)), "adlists.list")
loadedgroups = []
loadedlists = []
headers = {}
logged = False
PHMARKER = '[phtool]'
APIURL = ""
APIPASSWORD = ""
try:
  script_name = os.path.basename(__file__)
except NameError:
  script_name = os.path.basename(sys.argv[0])
ini_file = f'{os.path.splitext(script_name)[0]}.ini'


# Classes
class OneGroup:
  def __init__(self, groupid: int = None, name: str = None, enabled: bool = False, comment: str = None):
    self.id = groupid
    self.name = name
    self._enabled = enabled
    self._comment = comment

  def __repr__(self):
    return f'Class: {__class__.__name__} , name: {self.name}, enabled: {self._enabled}, id: {self.id}, comment: {self._comment}'

  def __str__(self):
    return f'Class: {__class__.__name__} , name: {self.name}, enabled: {self._enabled}, id: {self.id}, comment: {self._comment}'

  @property
  def comment(self):
    if self._comment is None:
      return PHMARKER
    return self._comment if self._comment.__contains__(PHMARKER) else f'{PHMARKER} {self._comment}'

  @comment.setter
  def comment(self, com: str = ""):
    self._comment = com if com.__contains__(PHMARKER) else f'{PHMARKER} {com}'

  @property
  def enabled(self):
    return True if self._enabled in ['true', '1', 1, 'yes'] else False

  @enabled.setter
  def enabled(self, value):
    self._enabled = value


class OneList:
  def __init__(self, url: str, groups: str = "default", comment: str = "None", listtype: str = 'block',
               enabled: bool = False):
    self._url: str = url
    self._group: List[str] = groups.split(',')
    self._comment: str = comment
    self._groups_id: List[int] = []  # most of the time group id is not create when the file is loaded
    self._listtype: str = listtype if listtype in ['allow', 'block'] else 'block'
    self._enabled: bool = enabled

  def __repr__(self):
    return f'Class: {__class__.__name__} , url: {self.url}, enabled: {self._enabled}, group: {self._group}, listtype: {self._listtype}, comment: {self._comment}'

  def __str__(self):
    return f'Class: {__class__.__name__} , url: {self.url}, enabled: {self._enabled}, group: {self._group}, listtype: {self._listtype}, comment: {self._comment}'

  @property
  def url(self):
    return self._url

  @property
  def groups(self):
    return self._group

  @property
  def comment(self):
    if self._comment is None:
      return PHMARKER
    return self._comment if self._comment.__contains__(PHMARKER) else f'{PHMARKER} {self._comment}'

  @comment.setter
  def comment(self, com: str = ""):
    self._comment = com if com.__contains__(PHMARKER) else f'{PHMARKER} {com}'

  @property
  def groups_id(self):
    return self._groups_id

  @groups_id.setter
  def groups_id(self, group_id: List[int]):
    self._groups_id = group_id

  @property
  def listtype(self):
    return self._listtype

  @listtype.setter
  def listtype(self, listtype: str = ''):
    self._listtype = listtype if listtype in ['allow', 'block'] else 'block'

  @property
  def enabled(self):
    return self._enabled

  @enabled.setter
  def enabled(self, value):
    self._enabled = value


class OneDomain:
  def __init__(self, domain: str = "", groups: str = "default", comment: str = "None", domaintype: str = 'deny',
               enabled: bool = True):
    self._domain: str = domain
    self._groups: List[str] = groups.split(',')
    self._comment: str = comment
    self._groups_id: List[int] = []  # most of the time group id is not create when the file is loaded
    self._domaintype: str = domaintype
    self._enabled: bool = enabled

  def __repr__(self):
    return f'Class: {__class__.__name__} , domain: {self.domain}, type: {self._domaintype}, enabled: {self._enabled}, groups: {self._groups}, comment: {self._comment}'

  def __str__(self):
    return f'Class: {__class__.__name__} , domain: {self.domain}, type: {self._domaintype}, enabled: {self._enabled}, groups: {self._groups}, comment: {self._comment}'

  @property
  def enabled(self) -> bool:
    return self._enabled
    # return self._enabled.lower() in ["true", "1", "on", "t", "y", "yes"]

  @enabled.setter
  def enabled(self, value: bool):
    self._enabled = value

  @property
  def domain(self):
    return self._domain

  @property
  def groups(self):
    return self._groups

  @property
  def comment(self):
    if self._comment is None:
      return PHMARKER
    return self._comment if self._comment.__contains__(PHMARKER) else f'{PHMARKER} {self._comment}'

  @comment.setter
  def comment(self, com: str = ""):
    self._comment = com if com.__contains__(PHMARKER) else f'{PHMARKER} {com}'

  @property
  def groups_id(self):
    return self._groups_id

  @groups_id.setter
  def groups_id(self, groups_id: List[int]):
    self._groups_id = groups_id

  @property
  def domaintype(self):
    return self._domaintype

  @domaintype.setter
  def type(self, domaintype: str = ""):
    self._domaintype = domaintype if domaintype in ['allow', 'allow-regex', 'deny', 'deny-regex'] else 'deny'


class OneClient:
  def __init__(self, client: str = "", group: str = "Default", comment: str = "None"):
    self._client: str = client
    self._group: List[str] = group.split(',')
    self._comment: str = comment
    self._groups_id: List[int] = []  # most of the time group id is not create when the file is loaded

  def __repr__(self):
    return f'Class: {__class__.__name__} , client: {self._client}, group: {self._group}, id: {self.id}, comment: {self._comment}'

  def __str__(self):
    return f'Class: {__class__.__name__} , client: {self._client}, group: {self._group}, id: {self.id}, comment: {self._comment}'

  @property
  def client(self):
    return self._client

  @client.setter
  def client(self, value: str):
    self._client = value

  @property
  def groups(self):
    return self._group

  @property
  def comment(self):
    if self._comment is None:
      return PHMARKER
    return self._comment if self._comment.__contains__(PHMARKER) else f'{PHMARKER} {self._comment}'

  @comment.setter
  def comment(self, com: str = ""):
    self._comment = com if com.__contains__(PHMARKER) else f'{PHMARKER} {com}'

  @property
  def groups_id(self):
    return self._groups_id

  @groups_id.setter
  def groups_id(self, group_id: List[int]):
    self._groups_id = group_id


# Functions
# generic query function
def getpostapi(apiconfig: {} = None, path: str = "", method: str = "get", payload: {} = None,
               dryrun: bool = True) -> json:
  """
  generic function to query api: https://ftl.pi-hole.net/master/docs/
  :param dryrun:
  :param apiconfig:
  :param path:
  :param method: GET or POST
  :param payload: json payload to send to the api
  :return: response json or text
  """
  url = f'https://{apiconfig.get("fqdn")}/api/{path}'
  data = json.dumps(payload)

  # req with method get or path with auth are executed whatever is the dryrun flag.
  if method.lower() != 'get' and not path.startswith('auth') and dryrun:
    logger.warning(f'Dry run enabled: {method} to {url} not performed, payload: {payload}')
    # return dummy object
    return {"clients": [{"id": "None", "ip": "no_url"}],
            "domains": [{"id": "None", "domain": "no_url"}],
            "groups": [{"id": "None", "name": "no_url"}],
            "lists": [{"id": "None", "address": "no_url"}],
            "processed": {"errors": "", "success": ""}}
  else:
    r = Request(method=method, url=url, data=data)
    prepped = apiconfig.get('session').prepare_request(r)
    logger.debug(
      f'method: {prepped.method}, url: {prepped.url}, headers: {prepped.headers}, data: {prepped.body} / {data}')
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
        if path in ['lists/', 'groups/', 'domains/', 'clients/']:
          logger.info('delete: {path}')
      if method == 'POST':
        logger.info(f'POST, status: {resp.status_code}, url: {url}')
      return {}
    if resp.status_code in [200, 201, 202, 204]:
      try:
        data = resp.json()
      except requests.JSONDecodeError:
        logger.error(f'not a json: {resp.text}, type: {r.headers.get("Content-type")}')
        if path == 'auth':
          sys.exit(1)
    else:
      logger.error(f'RC: {resp.status_code}, url: {url}, content: {resp.text}')
      if path == 'auth':
        sys.exit(1)

  logger.debug(f'response json: {data}, url: {url}, txt:{resp.text}')
  return data


# function query the api
def get_session_token(apiconfig: {} = None, password: str = "") -> {}:
  payload = {"password": password}
  logger.debug(f'payload: {payload}')
  data = getpostapi(apiconfig=apiconfig, path='auth', method='post', payload=payload, dryrun=False)

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
  sessions = getpostapi(path='auth/sessions', method='get', apiconfig=apiconfig, payload={}, dryrun=False)
  logger.debug(f'active sessions: {sessions}')
  logger.info(f'active sessions before closing this one:{len(sessions['sessions'])}')
  c = 0
  if close_all:
    for s in sessions['sessions']:
      if s['current_session'] == False and 'python' in s['user_agent']:
        c += 1
        data = getpostapi(path=f'auth/session/{s["id"]}', method='delete', apiconfig=apiconfig, dryrun=False)
        logger.debug(f'deleted session: {s["id"]}, agent: {s["user_agent"]}, data: {data}')

  data = getpostapi(path='auth', method='delete', apiconfig=apiconfig, dryrun=False)
  logger.debug(f'json: {data}')
  logger.info(f'Closed sessions: {c + 1}')


def get_version(apiconfig: {} = None) -> {}:
  version = getpostapi(path='info/version', apiconfig=apiconfig, method='GET')
  logger.debug(f'type: {type(version)}, json: {version}')
  return version


# Lists
def get_lists(apiconfig: {} = None) -> {}:
  data = getpostapi(path='lists', apiconfig=apiconfig, method='GET')
  lists = data['lists']
  took = data['took']
  logger.debug(f'# of lists: {len(lists)}, took: {took}')
  return lists


def add_lists(apiconfig: {} = None, list: OneList = None, replace: bool = False, dryrun: bool = True) -> any:
  payload = {'address': list.url, 'type': list.listtype, 'groups': list.groups_id,
             'comment': list.comment,
             'enabled': True}
  if replace:
    logger.debug(f'Replacing list: {payload}')
    data = getpostapi(path='lists', method='PUT', apiconfig=apiconfig, payload=payload, dryrun=dryrun)
  else:
    logger.debug(f'adding list: {payload}')
    data = getpostapi(path='lists', method='POST', apiconfig=apiconfig, payload=payload, dryrun=dryrun)
  logger.debug(f'json: {data}')
  return data


def remove_lists(listtype: str = 'phtool', apiconfig: {} = None, dryrun: bool = True) -> {}:
  apilists = get_lists(apiconfig=apiconfig)
  todelete = None
  if len(apilists) == 0:
    logger.warning(f'No lists to delete.')
    return

  if listtype == 'mine':
    todelete = list(filter(lambda x: x['comment'].__contains__(PHMARKER), apilists))
  if listtype == 'all':
    todelete = apilists['lists']
  if listtype == 'reset':
    todelete = list(filter(lambda x: x['comment'] not in 'Pi-hole defaults', apilists))

  logger.debug(f'requested: {listtype}, # to delete: {len(todelete)} lists to delete: {todelete}')
  logger.info(f'requested: {listtype}, # to delete: {len(todelete)}')
  c = 0
  items = []
  for l in todelete:
    payload = {'item': l['address'], 'type': l['type']}
    items.append(payload)
    c += 1
  if len(items) > 0:
    data = getpostapi(path=f'lists:batchDelete', method='POST', apiconfig=apiconfig, payload=items, dryrun=dryrun)
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
  mytype = tmp[0]
  if len(tmp) == 1:
    kind = 'exact'
  else:
    kind = tmp[1] if tmp[1] == 'regex' else 'exact'
  return mytype, kind


def add_domains(apiconfig: {} = None, domain: OneDomain = None, replace: bool = False, dryrun: bool = True) -> any:
  mytype, kind = get_type_kind(domain.domaintype)
  if replace:
    payload = {'type': mytype, 'kind': kind, 'comment': domain.comment,
               'groups': domain.groups_id, 'enabled': domain.enabled}
    logger.debug(fr'Replacing domain: {payload}')
    data = getpostapi(path=f'domains/{mytype}/{kind}/{domain.domain}', method='PUT', apiconfig=apiconfig,
                      payload=payload, dryrun=dryrun)
  else:
    payload = {'domain': domain.domain, 'comment': domain.comment,
               'groups': domain.groups_id, 'enabled': domain.enabled}
    logger.debug(fr'adding domain: {payload}')
    data = getpostapi(path=f'domains/{mytype}/{kind}', method='POST', apiconfig=apiconfig, payload=payload,
                      dryrun=dryrun)
  logger.debug(fr'#errors: {len(data["processed"]["errors"])}, processed: {data['processed']}')

  if len(data['processed']['errors']) > 0:
    errorlist = " ".join([f'{e["item"]}: {e["error"]}' for e in data['processed']['errors']])
    logger.error(f'error while adding domain: {errorlist}')
  if len(data['processed']['success']) > 0:
    successlist = " ".join([f'{e["item"]}' for e in data['processed']['success']])
    logger.info(fr'added domain:{successlist}, enabled: {domain.enabled}, replace: {replace}')

  return data


def remove_domains(domaintype: str = 'phtool', apiconfig: {} = None, dryrun: bool = True) -> {}:
  apidomains = get_domains(apiconfig=apiconfig)
  todelete = list()
  if len(apidomains) == 0:
    logger.warning(f'No lists to delete.')
    return

  # logger.debug(f'apidomains: {apidomains}')
  if domaintype == 'mine':
    for d in apidomains:
      if d['comment'] is not None and d['comment'].__contains__(PHMARKER):
        todelete.append(d)
        logger.debug(fr'url: {d['domain']}, comment: {d["comment"]}')
    logger.debug(fr'todelete: {todelete}')
  if domaintype == 'all':
    todelete = apidomains

  logger.debug(f'requested: {domaintype}, # to delete: {len(todelete)} lists to delete: {todelete}')
  logger.info(f'requested: {domaintype}, # to delete: {len(todelete)}')
  c = 0
  items = []
  for l in todelete:
    payload = {'item': l['domain'], 'type': l['type'], 'kind': l['kind']}
    items.append(payload)
    c += 1
  if len(items) > 0:
    data = getpostapi(path=f'domains:batchDelete', method='POST', apiconfig=apiconfig, payload=items, dryrun=dryrun)
    if data is None:
      logger.warning(f'not deleted list: {list(map(lambda x: x["address"], items))}')
      c = 0
  else:
    logger.warning(f'Nothing to delete with type {domaintype}')
    logger.debug(f'todelete: {todelete}')

  logger.info(f'{c}/{len(todelete)} deleted.')


# groups
def load_groups(filename: str = None) -> List[OneGroup]:
  groups = list()
  check_file(filename)

  logger.debug(f'Loading file: {filename}')
  with open(filename, mode="+r") as f:
    lines = f.readlines()

  if len(lines) < 1:
    logger.error(f'No data in file: {filename}')

  comment = 'No comment'
  i = 0
  a = 0
  for line in lines:
    i += 1
    # remove line return and split on #
    tmp = line.strip('\n').split('#', maxsplit=1)
    logger.debug(fr'len: {len(tmp)}, tmp: {tmp[0]}, comment: {tmp[1]}, line: {line}')

    group = ''
    enabled = False

    # line start with #
    if tmp[0] == '':
      comment = line
      payload = []
    else:
      payload = tmp[0].split(None)
      comment = tmp[1] if len(tmp) > 1 else comment
      group = str(payload[0])
      # No group given, assigning to Default
      if len(payload) > 1:
        enabled = eval(payload[1])
    comment = comment if comment.__contains__(PHMARKER) else f'{PHMARKER} {comment}'
    logger.debug(fr'len: {len(payload)}, payload: {payload}, comment: {comment}, line: {line}')
    # ignore duplicate
    if group != '' and group not in [g.name for g in groups]:
      logger.debug(fr'loaded group: {group}, enabled: {enabled}, comment: {comment}')
      l = OneGroup(name=group, enabled=enabled, comment=comment)
      # add object if domain is not found and not empty
      a += 1
      groups.append(l)
    else:
      logger.warning(f'group ({group}) already present or empty.')

  logger.info(f'found {len(groups)} unique groups out of {a} lines in {os.path.basename(filename)}.')
  return groups


def get_groups(apiconfig: {} = None, simplified: bool = True) -> {}:
  groups = getpostapi(path='groups/', apiconfig=apiconfig)
  logger.debug(f'groups: {groups["groups"]}')
  if simplified:
    ngroups = dict(map(lambda x: (x['name'], x['id']), groups['groups']))
    logger.debug(f'ngroups: {ngroups}')
    return ngroups
  else:
    ogroups = list()
    for g in groups['groups']:
      ogroups.append(OneGroup(groupid=int(g['id']), name=g['name'], enabled=g['enabled'], comment=g['comment']))
    logger.debug(f'ogroups: {ogroups}')
    return ogroups


def add_groups(groups: List[str] = None, apiconfig: {} = None, dryrun: bool = True, replace: bool = False) -> {}:
  if groups is None:
    logger.warning('No group given. Exiting')
    return {}
  payload = {'name': groups, 'comment': f'{PHMARKER} {" ".join(groups)}', 'enabled': True}
  if replace:
    r = getpostapi(path='groups', method='POST', apiconfig=apiconfig, payload=payload, dryrun=dryrun)
  else:
    for g in groups:
      r = getpostapi(path=f'groups/{g}', method='PUT', apiconfig=apiconfig, payload=payload, dryrun=dryrun)
      logger.debug(f'json: {r}')

  if r['processed'] == 'null':
    logger.error(f'Error while adding group: {r}')
  for e in r['processed']['errors']:
    logger.error(f'Error while adding group: {e["item"]}, {e["error"]}')
  return r


def update_groups(groups: List[OneGroup], apiconfig: {} = None, dryrun: bool = True, create: bool = True) -> {}:
  apigroups = get_groups(apiconfig=apiconfig)
  groupnames = apigroups.keys()
  results = []
  # only update existing groups: no id change, only comments and or enabled
  for g in groups:
    # update
    if g.name in groupnames:
      payload = {"name": g.name, "comment": g.comment, "enabled": g.enabled}
      r = getpostapi(path=f'groups/{g.name}', method='PUT', apiconfig=apiconfig, payload=payload, dryrun=dryrun)
    elif create:
      payload = {"name": g.name, "comment": g.comment, "enabled": g.enabled}
      r = getpostapi(path=f'groups', method='POST', apiconfig=apiconfig, payload=payload, dryrun=dryrun)
    logger.debug(f'json: {r}')

    if r['processed'] == 'null':
      logger.error(f'Error while adding group: {r}')
      for e in r['processed']['errors']:
        logger.error(f'Error while adding group: {e["item"]}, {e["error"]}')

    results.append(r)
  logger.debug(f'results: {results}')
  return results


def remove_groups(apiconfig: {} = None, scope: str = "", dryrun: bool = True):
  apilists = get_lists(apiconfig=apiconfig)
  apidomains = get_domains(apiconfig=apiconfig)
  apiclients = get_domains(apiconfig=apiconfig)
  todelete = []
  if len(apiclients) > 0 or len(apidomains) > 0 or len(apilists) > 0:
    logger.warning(
      'one of lists,domains or client is not empty. To keep structure integrity, groups are not removed. Exiting')
    return {}
  apigroups = get_groups(apiconfig=apiconfig, simplified=False)

  if scope == 'mine':
    templist = list(filter(lambda x: x.comment.__contains__(PHMARKER) and x.name != 'Default', apigroups))
    # logger.info(f'templist: {[t.name for t in templist]}')
    todelete = list(map(lambda y: y.name, templist))
  if scope == 'all':
    todelete = list(map(lambda x: x.name, apigroups))
  if scope == 'reset':
    todelete = list(filter(lambda x: x.name != 'Default', apigroups))

  items = []
  for g in todelete:
    payload = {'item': g}
    items.append(payload)
  logger.debug(f'groups deletion for {scope}: {items}, todelete: {todelete}')
  logger.info(f'groups deletion for {scope}: {items}')
  r = getpostapi(path=f'groups:batchDelete', method='POST', apiconfig=apiconfig, payload=items, dryrun=dryrun)
  logger.debug(f'response: {r}')
  return r


# Clients
def load_clients(filename: str = None) -> List[OneClient]:
  clients = []
  check_file(filename)

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
    # remove line return and split on #
    tmp = line.strip('\n').split('#', maxsplit=1)
    logger.debug(fr'len: {len(tmp)}, tmp: {tmp}, comment: {comment}, line: {line}')

    client = ''
    group = 'Default'
    # line start with #
    if tmp[0] == '':
      comment = line
      payload = []
    else:
      payload = tmp[0].split(None)
      comment = tmp[1] if len(tmp) > 1 else comment
      client = str(payload[0])
      # No group given, assigning to Default
      if len(payload) > 1:
        group = payload[1]
      if len(payload) > 2:
        group = payload[2]
        # ignore other infos
        # client += f' {payload[1]}' if payload[1] != 'None' else ''
    comment = comment if comment.__contains__(PHMARKER) else f'{PHMARKER} {comment}'
    logger.debug(fr'len: {len(payload)}, payload: {payload}, comment: {comment}, line: {line}')
    # ignore duplicate
    if client != '' and client not in [ll.client for ll in clients]:
      logger.debug(fr'loaded client: {client}, type: {type}, group: {group}, comment: {comment}')
      l = OneClient(client=client, group=group, comment=comment)
      # add object if domain is not found and not empty
      a += 1
      clients.append(l)
    else:
      logger.warning(f'client ({client}) already present or empty.')

  logger.info(f'found {len(clients)} unique clients out of {a} lines in {os.path.basename(filename)}.')
  return clients


def get_clients(apiconfig: {} = None) -> {}:
  data = getpostapi(path='clients', apiconfig=apiconfig, method='GET')
  clients = data['clients']
  took = data['took']
  logger.debug(f'# of clients: {len(clients)}, took: {took}')
  return clients


def add_clients(apiconfig: {} = None, client: OneClient = None, replace: bool = False, dryrun: bool = True) -> any:
  if replace:
    payload = {'comment': client.comment, 'groups': client.groups_id}
    logger.debug(fr'Replacing client: {payload}')
    data = getpostapi(path=f'clients/{client.client}', method='PUT', apiconfig=apiconfig,
                      payload=payload, dryrun=dryrun)
  else:
    payload = {'client': client.client, 'comment': client.comment, 'groups': client.groups_id}
    logger.debug(fr'adding client: {payload}')
    data = getpostapi(path=f'clients', method='POST', apiconfig=apiconfig, payload=payload, dryrun=dryrun)
  logger.debug(fr'#errors: {len(data["processed"]["errors"])}, processed: {data['processed']}')

  if len(data['processed']['errors']) > 0:
    errorlist = " ".join([f'{e["item"]}: {e["error"]}' for e in data['processed']['errors']])
    logger.error(f'error while adding client: {errorlist}')
  if len(data['processed']['success']) > 0:
    successlist = " ".join([f'{e["item"]}' for e in data['processed']['success']])
    logger.info(fr'added client:{successlist}')

  return data


def remove_clients(clienttype: str = 'phtool', apiconfig: {} = None, dryrun: bool = True) -> {}:
  apiclients = get_clients(apiconfig=apiconfig)
  todelete = list()
  if len(apiclients) == 0:
    logger.warning(f'No lists to delete.')
    return

  # logger.debug(f'apiclients: {apiclients}')
  if clienttype == 'mine':
    for c in apiclients:
      if c['comment'] is not None and c['comment'].__contains__(PHMARKER):
        todelete.append(c)
        logger.debug(fr'url: {c['client']}, comment: {c["comment"]}')
    logger.debug(fr'todelete: {todelete}')
  if clienttype == 'all':
    todelete = apiclients

  logger.debug(f'requested: {clienttype}, # to delete: {len(todelete)} lists to delete: {todelete}')
  logger.info(f'requested: {clienttype}, # to delete: {len(todelete)}')
  c = 0
  items = []
  for l in todelete:
    payload = {'item': l['client']}
    items.append(payload)
    c += 1
  if len(items) > 0:
    data = getpostapi(path=f'clients:batchDelete', method='POST', apiconfig=apiconfig, payload=items, dryrun=dryrun)
    if data is None:
      logger.warning(f'not deleted list: {list(map(lambda x: x["address"], items))}')
      c = 0
  else:
    logger.warning(f'Nothing to delete with type {clienttype}')
    logger.debug(f'todelete: {todelete}')

  logger.info(f'{c}/{len(todelete)} deleted.')


# Exports
def export_lists(apiconfig):
  filename = f'{LDIR}{os.path.sep}lists.list'
  if os.path.exists(filename):
    logger.error(f'File already exists: {filename}')
    sys.exit(1)

  apilists = get_lists(apiconfig=apiconfig)
  apigroups = get_groups(apiconfig=apiconfig)
  inv_groups = {v: k for k, v in apigroups.items()}
  logger.debug(f'reversed groups: {inv_groups}')
  lines = list()
  for l in apilists:
    logger.debug(f'list: {l}')
    groups = [inv_groups[gc] for gc in l["groups"]]
    logger.debug(f'groups: {groups}')
    line = f'{l["address"]} {",".join(groups)} {l["type"]} {l["enabled"]} #{l["comment"].strip()}\n'
    logger.debug(f'line: {line}')
    if len(line) > 0:
      lines.append(line)

  with open(filename, 'w') as f:
    f.writelines(lines)
  logger.info(f'{len(lines)} lines written to {filename}')


def export_domains(apiconfig: {} = None) -> None:
  filename = f'{LDIR}{os.path.sep}domains.list'
  if os.path.exists(filename):
    logger.error(f'File already exists: {filename}')
    sys.exit(1)

  apidomains = get_domains(apiconfig=apiconfig)
  apigroups = get_groups(apiconfig=apiconfig)
  inv_groups = {v: k for k, v in apigroups.items()}
  logger.debug(f'reversed groups: {inv_groups}')
  lines = list()
  for d in apidomains:
    logger.debug(f'domain: {d}')
    groups = [inv_groups[gc] for gc in d["groups"]]
    logger.debug(f'groups: {groups}')
    line = f'{d["domain"]} {d["type"]}{'-' + d["kind"] if d["kind"] != "exact" else ""} {",".join(groups)} {d['enabled']} #{d["comment"]}\n'
    logger.debug(f'line: {line}')
    if len(line) > 0:
      lines.append(line)

  with open(filename, 'w') as f:
    f.writelines(lines)
  logger.info(f'{len(lines)} lines written to {filename}')


def export_clients(apiconfig: {} = None) -> None:
  filename = f'{LDIR}{os.path.sep}clients.list'
  if os.path.exists(filename):
    logger.error(f'File already exists: {filename}')
    sys.exit(1)

  apiclients = get_clients(apiconfig=apiconfig)
  apigroups = get_groups(apiconfig=apiconfig)
  inv_groups = {v: k for k, v in apigroups.items()}
  logger.debug(f'reversed groups: {inv_groups}')
  lines = list()
  for c in apiclients:
    groups = []
    logger.debug(f'client: {c}')
    for gc in c["groups"]:
      logger.debug(f'gc: {gc}')
      groups.append(inv_groups[gc])
    line = f'{c["client"]} {c["name"]} {",".join(groups)} #{c["comment"]}\n'
    logger.debug(f'line: {line}')
    if len(line) > 1:
      lines.append(line)

  with open(filename, 'w') as f:
    f.writelines(lines)
  logger.info(f'{len(lines)} lines written to {filename}')


def export_groups(apiconfig: {} = None) -> None:
  filename = f'{LDIR}{os.path.sep}groups.list'
  if os.path.exists(filename):
    logger.error(f'File already exists: {filename}')
    sys.exit(1)

  apigroups = get_groups(apiconfig=apiconfig, simplified=False)
  lines = list()
  for g in apigroups:
    logger.debug(f'group: {g.name},{g.enabled} {g.comment}')
    line = f'{g.name} {g.enabled} #{g.comment}\n'
    logger.debug(f'line: {line}')
    if len(line) > 1:
      lines.append(line)

  with open(filename, 'w') as f:
    f.writelines(lines)
  logger.info(f'{len(lines)} lines written to {filename}')


########################################################################################
def show_version(version: {} = None):
  if version is None:
    logger.warning('No version given. Exiting')
  # logger.debug(f'version: {version}')
  logger.info(
    f'version: docker {version["version"]["docker"]["local"]}, core: {version["version"]["core"]["local"]["version"]}/{version["version"]["core"]["remote"]["version"]}\
  , web: {version["version"]["web"]["local"]["version"]}/{version["version"]["web"]["remote"]["version"]}\
  , ftl: {version["version"]["ftl"]["local"]["version"]}/{version["version"]["ftl"]["remote"]["version"]}')


def check_file(filename: str = ''):
  if filename is None:
    logger.error(f'No file given. Exiting')
    sys.exit(1)
  if not os.path.isfile(filename):
    logger.error(f'file not found ({filename}). Exiting')
    sys.exit(1)


def load_domains(filename: str = None) -> List[OneDomain]:
  domains = []
  check_file(filename)

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
    domaintype = 'deny'
    group = 'Default'
    # line start with #
    if tmp[0] == '':
      comment = line
      payload = []
      enabled = False
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
          domaintype = payload[1]
          group = payload[2] if len(payload) >= 3 else group
        else:
          # No type, so next one is group
          group = payload[1]
      enabled = eval(payload[3]) if len(payload) >= 4 else False
    comment = comment if comment.__contains__(PHMARKER) else f'{PHMARKER} {comment}'
    logger.debug(fr'len: {len(payload)}, payload: {payload}, comment: {comment}, enabled: {enabled}, line: {line}')
    if domain != '' and domain not in [ll.domain for ll in domains]:
      logger.debug(
        fr'loaded domain: {domain}, type: {domaintype}, group: {group}, enabled: {enabled}, comment: {comment}')
      l = OneDomain(domain=domain, domaintype=domaintype, groups=group, comment=comment, enabled=enabled)
      # add object if domain is not found and not empty
      a += 1
      domains.append(l)
    else:
      logger.warning(f'domain ({domain}) already present or empty.')

  logger.info(f'found {len(domains)} unique domains out of {a} lines in {os.path.basename(filename)}.')
  return domains


def load_lists(filename: str = None) -> List[OneList]:
  lists = []
  check_file(filename)
  logger.debug(f'Loading file: {filename}')
  with open(filename, mode="+r") as f:
    lines = f.readlines()

  if len(lines) < 1:
    logger.error(f'No file read: {filename}')

  comment = 'No comment'
  i = 0
  a = 0
  for line in lines:
    # TODO
    i += 1
    # split on spaces
    tmp = line.strip('\n').split('#', maxsplit=1)
    logger.debug(f'len: {len(tmp)}, payload: {tmp}, comment: {comment}, line: {line}')

    url = ''
    type = 'block'
    group = 'Default'
    enabled = False
    # line start with #
    if tmp[0] == '':
      comment = line
      payload = []
    else:
      payload = tmp[0].split(None)
      comment = tmp[1] if len(tmp) > 1 else comment
      url = payload[0]
      enabled = eval(payload[3]) if len(payload) >= 4 else False
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
    comment = comment if comment.__contains__(PHMARKER) else f'{PHMARKER} {comment}'
    logger.debug(f'len: {len(payload)}, payload: {payload}, comment: {comment}, line: {line}')
    if url != '' and url not in [ll.url for ll in lists]:
      logger.debug(f'adding list: {url}, type: {type}, group: {group}, enabled: {enabled}, comment: {comment}')
      l = OneList(url=url, listtype=type, groups=group, comment=comment, enabled=enabled)
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
    for g in l.groups:
      loaded_groups.add(g)
  logger.debug(f'loaded_groups: {loaded_groups}')
  return list(loaded_groups)


def process_lists(apiconfig: {} = None, api_groups=None, filename: str = None, replace: bool = False,
                  dryrun: bool = True) -> {}:
  loaded_list = load_lists(filename)
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
    r = add_groups(apiconfig=apiconfig, groups=newgroups, dryrun=dryrun)
    logger.debug(f'add groups result: {r}')
    # fetch new api groups
    api_groups = get_groups(apiconfig=apiconfig)

  # check for new lists
  apilists = get_lists(apiconfig=apiconfig)
  adresses = list(map(lambda x: x['address'], apilists))
  newlists = list()
  for l in loaded_list:
    if l.url not in adresses:
      # New url found, need to add group ids:
      gid = []
      for g in l.groups:
        gid.append(api_groups.get(g))
      l.groups_id = gid
      logger.debug(f'list to add: {l.url}, {l.groups}/{l.groups_id}, {l.comment}')
      newlists.append(l)
      r = add_lists(apiconfig=apiconfig, list=l, replace=replace, dryrun=dryrun)
      logger.debug(f'addList result: {r}')
      logger.info(f'addlist result: id: {r["lists"][0]["id"]}, address: {r["lists"][0]["address"]}')

  logger.info(f'# of newLists to add: {len(newlists)}')


def process_domains(apiconfig: {} = None, api_groups=None, filename: str = None, replace: bool = False,
                    dryrun: bool = True) -> {}:
  loaded_domains = load_domains(filename)
  logger.debug(fr'loaded_domains: {[d.domain for d in loaded_domains]}')
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
    r = add_groups(apiconfig=apiconfig, groups=newgroups, dryrun=dryrun)
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
    replace = False
    # search in pihole domains and compare domain, type & kind
    for a in apidomains:
      if a['domain'] == d.domain:
        logger.debug(f'domain match: {a} / {d}')
        domaintype, kind = get_type_kind(d.domaintype)
        found = (domaintype == a['type'] and kind == a['kind'])
        if d.enabled != a['enabled']:
          logger.debug(f'enabled is diff: {d} != {a}')
          found = False
          replace = True
        break
    if not found:
      logger.debug(fr'not found domain {d.domain}, type:{d.domaintype}, enabled: {d.enabled}')
      # New url found, need to add group ids:
      gid = []
      for g in d.groups:
        gid.append(api_groups.get(g))
      d.groups_id = gid
      logger.debug(
        fr'list to add: {d.domain}, {d.groups}/{d.groups_id}, {d.comment}, enabled: {d.enabled}, replace: {replace}')
      newdomains.append(d)
      r = add_domains(apiconfig=apiconfig, domain=d, replace=replace, dryrun=dryrun)

  logger.info(f'# of new Domains to add: {len(newdomains)}')


# Process clients
def process_clients(apiconfig: {} = None, api_groups=None, filename: str = None, replace: bool = False,
                    dryrun: bool = True) -> {}:
  loaded_clients = load_clients(filename)
  logger.debug(fr'loaded_clients: {[c.client for c in loaded_clients]}')
  loaded_groups = get_list_of_groups_from_loaded_list(loaded_clients)

  # get array of existing groups.
  logger.debug(f'loaded_groups: {loaded_groups}')
  logger.debug(f'api groups: {api_groups}')
  newgroups = []
  # create a list of not existing groups
  for g in loaded_groups:
    if g not in api_groups.keys():
      newgroups.append(g)
      logger.debug(f'new group: {g}')
  logger.debug(f'new groups: {len(newgroups)}, {newgroups}')
  # create missing groups
  if len(newgroups) != 0 and not dryrun:
    r = add_groups(apiconfig=apiconfig, groups=newgroups, dryrun=dryrun)
    logger.debug(f'add groups result: {r}')
    # fetch new api groups
    api_groups = get_groups(apiconfig=apiconfig)

  # check for new lists
  apiclients = get_clients(apiconfig=apiconfig)
  newclients = list()
  clientsapinamelist = list()
  logger.debug(f'api clients: {apiclients}')
  # get list of clients names
  clientsapinamelist = list(map(lambda x: x['client'], apiclients))

  # parse clients loaded from file.
  for c in loaded_clients:
    found = False
    replace = False
    # search in pihole clients and compare client, type & kind
    for a in apiclients:
      if c.client in clientsapinamelist:
        found = True
        break
    if not found:
      logger.debug(fr'client {c.client} not found in ({clientsapinamelist}), groups: {c.groups}')
      # New url found, need to add group ids:
      gid = []
      for g in c.groups:
        gid.append(api_groups.get(g))
      c.groups_id = gid
      logger.debug(
        fr'list to add: {c.client}, {c.groups}/{c.groups_id}, {c.comment}, replace: {replace}')
      newclients.append(c)
      r = add_clients(apiconfig=apiconfig, client=c, replace=replace, dryrun=dryrun)

  logger.info(f'# of new clients to add: {len(newclients)}')


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
  parser.add_argument('-l', '--lists', action='store', help='load lists found in <file>')
  parser.add_argument('-L', '--remove_lists', choices=['all', 'mine', 'reset'], help='remove lists: all, mine, reset')
  parser.add_argument('-d', '--domains', action='store', help='load domains found in <file>')
  parser.add_argument('-D', '--remove_domains', choices=['all', 'mine'],
                      help='remove domains: all, mine, reset')
  parser.add_argument('-k', '--clients', action='store', help='load clients found in <file>')
  parser.add_argument('-K', '--remove_clients', choices=['all', 'mine', 'reset'],
                      help='remove clients: all,mine, reset')
  parser.add_argument('-g', '--groups', action='store', help='load groups found in <file>')
  parser.add_argument('-G', '--remove_groups', choices=['all', 'mine', 'reset'],
                      help='remove groups: all, mine, reset ')
  parser.add_argument('-u', '--update_groups', action='store', help='update groups found in <file>, no delete, no add')
  parser.add_argument('-c', '--conf', help='read config <file>,load <param> section')
  parser.add_argument('-e', '--export', choices=['clients', 'domains', 'groups', 'lists'],
                      help='export to file <name>.list, param is clients, domains, groups or lists')
  parser.add_argument('-r', '--replace', action='store_true', help='replace if possible groups and lists')
  parser.add_argument('-q', '--quiet', action='store_true', help='if set to true, output error only')
  parser.add_argument('-m', '--mail', action='store_true', help='send mail even when not run by cron')
  parser.add_argument('-x', '--execute', action='store_true', help='execute post and delete requests')
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

  # Lists
  if args.lists:
    process_lists(apiconfig=apiconfig, api_groups=groups, filename=args.lists, replace=args.replace,
                  dryrun=not args.execute)
  if args.remove_lists:
    remove_lists(apiconfig=apiconfig, listtype=args.remove_lists, dryrun=not args.execute)

  # Domains
  if args.domains:
    process_domains(apiconfig=apiconfig, api_groups=groups, filename=args.domains, replace=args.replace,
                    dryrun=not args.execute)

  if args.remove_domains:
    remove_domains(apiconfig=apiconfig, domaintype=args.remove_domains, dryrun=not args.execute)

  # Clients
  if args.clients:
    process_clients(apiconfig=apiconfig, api_groups=groups, filename=args.clients, replace=args.replace,
                    dryrun=not args.execute)

  if args.remove_clients:
    remove_clients(apiconfig=apiconfig, clienttype=args.remove_clients, dryrun=not args.execute)

  # Export
  if args.export == 'domains':
    export_domains(apiconfig=apiconfig)
  if args.export == 'lists':
    export_lists(apiconfig=apiconfig)
  if args.export == 'clients':
    export_clients(apiconfig=apiconfig)
  if args.export == 'groups':
    export_groups(apiconfig=apiconfig)

  # Groups
  if args.remove_groups:
    remove_groups(apiconfig=apiconfig, scope=args.remove_groups, dryrun=not args.execute)
  if args.update_groups:
    groups = load_groups(filename=args.update_groups)
    update_groups(apiconfig=apiconfig, groups=groups, dryrun=not args.execute, create=False)
  if args.groups:
    groups = load_groups(filename=args.groups)
    update_groups(apiconfig=apiconfig, groups=groups, dryrun=not args.execute, create=True)

  # close opened sessions
  if logged:
    data = close_session(apiconfig=apiconfig, close_all=True)


if __name__ == "__main__":
  logging.basicConfig(format='%(asctime)s;%(levelname)s:%(name)s:%(funcName)s - %(lineno)s:%(message)s',
                      level=logging.INFO)
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
