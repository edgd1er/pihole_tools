import os
import unittest
import sys

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/..")
#import phadlist
import phadlist


class TestOneXXInitAndMethods(unittest.TestCase):

  def test_oneGroup(self):
    name = "myname"
    gid = 125
    comment = "Comment"
    enabled = True

    l = phadlist.OneGroup(groupid=gid, name=name, enabled=enabled, comment=comment)
    self.assertEqual(l.name, name)
    self.assertEqual(l.id, gid)
    self.assertEqual(l.enabled, enabled)
    self.assertEqual(l.comment, f'{phadlist.PHMARKER} {comment}')

    l.enabled = 'unknown'
    self.assertEqual(l.enabled, False)
    l.enabled = False
    self.assertEqual(l.enabled, False)

  def test_oneClient(self):
    comment="comment1"
    client="client1"
    group="Default,ads"
    c = phadlist.OneClient(client=client, comment=comment, group=group)
    groups_id = [4, 8]
    c.groups_id = groups_id
    self.assertEqual(c.client, client)
    self.assertEqual(c.comment, f'{phadlist.PHMARKER} {comment}')
    self.assertEqual(c.groups, ["Default", "ads"])
    self.assertEqual(c.groups_id, groups_id)

  def test_oneDomain(self):
    domain = "mydomain"
    group = "default,test"
    comment = "Comment"
    dtype = 'deny'
    enabled = True
    d = phadlist.OneDomain(domain=domain, groups=group, comment=comment, domaintype=dtype, enabled=enabled)
    groups_id = [4, 8]
    d.groups_id = groups_id
    self.assertEqual(d.domain, domain)
    self.assertEqual(d.comment, f'{phadlist.PHMARKER} {comment}')
    self.assertEqual(d.domaintype, dtype)
    self.assertEqual(d.groups, group.split(','))
    self.assertEqual(d.groups_id, groups_id)
    self.assertEqual(d.enabled, enabled)

    dtype = 'allow-regex'
    d.type = dtype
    self.assertEqual(d.domaintype, dtype)

    dtype = 'unknown'
    d.type = dtype
    self.assertEqual(d.domaintype, 'deny')

  def test_oneList(self):
    url = "myurl"
    groups = "default,test"
    comment = "Comment"
    ltype = 'allow'
    enabled = True

    l = phadlist.OneList(url=url, groups=groups, comment=comment, listtype=ltype, enabled=enabled)
    self.assertEqual(l.url, url)
    self.assertEqual(l.groups, groups.split(','))
    self.assertEqual(l.comment, f'{phadlist.PHMARKER} {comment}')
    self.assertEqual(l.listtype, ltype)
    self.assertEqual(l.enabled, enabled)

    l.listtype = 'unknown'
    self.assertEqual(l.listtype, 'block')
    l.listtype = 'block'
    self.assertEqual(l.listtype, 'block')

if __name__ == '__main__':
  unittest.main()
