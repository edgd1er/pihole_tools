import unittest

import pihole.phadlist
from pihole.phadlist import load_groups, load_clients, load_domains, load_lists


class TestLoadXX(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    cls.fname_does_not_exist = 'unknownfile.txt'
    cls.fname_groups = "../pgroups-sample.list"
    cls.fname_clients = "../pclients-sample.list"
    cls.fname_domains = "../pdomains-sample.list"
    cls.fname_lists = "../padlists-sample.list"

  ########### Groups ###################
  def test_loadGroups_failed(self):
    with self.assertRaises(SystemExit) as cm:
      loaded_groups = load_groups(self.fname_does_not_exist)
    self.assertEqual(cm.exception.code, 1)

  def test_loadGroups_ok(self):
    loaded_groups = load_groups(self.fname_groups)
    self.assertEqual(1, len(loaded_groups))
    self.assertEqual("noAds", loaded_groups[0].name)
    self.assertTrue(loaded_groups[0].enabled)
    self.assertEqual("[phtool] block ads", loaded_groups[0].comment)

  ########### Clients ###################
  def test_loadClients_failed(self):
    with self.assertRaises(SystemExit) as cm:
      loaded_clients = load_clients(self.fname_does_not_exist)
    self.assertEqual(cm.exception.code, 1)

  def test_loadClients_ok(self):
    loaded_clients = load_clients(self.fname_clients)
    self.assertEqual(1, len(loaded_clients))
    self.assertEqual("client2", loaded_clients[0].client)
    self.assertEqual(["Default", "noads"], loaded_clients[0].groups)
    self.assertEqual("[phtool] test client", loaded_clients[0].comment)

  ########### Domains ###################
  def test_loadDomains_failed(self):
    with self.assertRaises(SystemExit) as cm:
      loaded_domains = load_domains(self.fname_does_not_exist)
    self.assertEqual(cm.exception.code, 1)

  def test_loadDomains_without_enabled_ok(self):
    # cdn.ravenjs.com allow Default #whitelist ravenjs
    res = "cdn.ravenjs.com allow Default #whitelist ravenjs".split("#")
    comment = pihole.phadlist.PHMARKER + " " + res[1]
    part1 = res[0].split(' ')
    domain = part1[0]
    domaintype = part1[1]
    enabled = False
    groups = part1[2].split(',')
    idx = 0
    loaded_domains = load_domains(self.fname_domains)
    self.assertEqual(3, len(loaded_domains))
    self.assertEqual(domain, loaded_domains[idx].domain)
    self.assertEqual(domaintype, loaded_domains[idx].domaintype)
    # when not defined, enabled is false
    self.assertEqual(enabled, loaded_domains[idx].enabled)
    self.assertEqual(groups, loaded_domains[idx].groups)
    self.assertEqual(comment, loaded_domains[idx].comment)

  def test_loadDomains_with_enabled_ok(self):
    # (\.|^)wakanim\.tv$ deny-regex True group1,group2 #Wakanim block
    res = "(\.|^)wakanim\.tv$ deny-regex group1,group2 True #Wakanim block".split("#")
    comment = pihole.phadlist.PHMARKER + " " + res[1]
    part1 = res[0].split(' ')
    domain = part1[0]
    domaintype = part1[1]
    enabled = part1[3]
    groups = part1[2].split(',')
    idx = 1
    loaded_domains = load_domains(self.fname_domains)
    self.assertEqual(3, len(loaded_domains))
    self.assertEqual(domain, loaded_domains[idx].domain)
    self.assertEqual(domaintype, loaded_domains[idx].domaintype)
    # when not defined, enabled is false
    self.assertEqual(enabled, loaded_domains[idx].enabled)
    self.assertEqual(groups, loaded_domains[idx].groups)
    self.assertEqual(comment, loaded_domains[idx].comment)

  ########### Lists ###################
  def test_loadLists_failed(self):
    with self.assertRaises(SystemExit) as cm:
      loaded_lists = load_lists(self.fname_does_not_exist)
    self.assertEqual(cm.exception.code, 1)

  def test_loadLists_without_enabled_ok(self):
    res="https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt noTrack,Default block #DisconTrack".split('#')
    comment = pihole.phadlist.PHMARKER + " " + res[1]
    part1 = res[0].split(' ')
    url = part1[0]
    group = part1[1]
    groups = group.split(',')
    listtype = part1[2]
    enabled = False
    idx = 0
    loaded_lists = load_lists(self.fname_lists)
    self.assertEqual(4, len(loaded_lists))
    self.assertEqual(url, loaded_lists[idx].url)
    self.assertEqual(groups, loaded_lists[idx].groups)
    self.assertEqual(enabled, loaded_lists[idx].enabled)
    self.assertEqual(listtype, loaded_lists[idx].listtype)
    self.assertEqual(comment, loaded_lists[idx].comment)

  def test_loadLists_with_enabled_ok(self):
    res="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts Default,group1 block #Pi-hole defaults".split('#')
    comment = pihole.phadlist.PHMARKER + " " + res[1]
    part1 = res[0].split(' ')
    url = part1[0]
    group = part1[1]
    groups = group.split(',')
    listtype = part1[2]
    enabled = part1[3]
    idx = 1
    loaded_lists = load_lists(self.fname_lists)
    self.assertEqual(4, len(loaded_lists))
    self.assertEqual(url, loaded_lists[idx].url)
    self.assertEqual(groups, loaded_lists[idx].groups)
    self.assertEqual(listtype, loaded_lists[idx].listtype)
    self.assertEqual(comment, loaded_lists[idx].comment)


if __name__ == '__main__':
  unittest.main(verbosity=1)
