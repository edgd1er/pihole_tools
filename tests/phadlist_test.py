import unittest

import pihole.phadlist
from pihole.phadlist import OneClient, OneDomain, OneList, OneGroup


class TestOneXXInitAndMethods(unittest.TestCase):

  def test_oneGroup(self):
    name = "myname"
    id = 125
    comment = "Comment"
    enabled = True

    l = OneGroup(groupid=id, name=name, enabled=enabled, comment=comment)
    self.assertEqual(l.name, name)
    self.assertEqual(l.id, id)
    self.assertEqual(l.enabled, enabled)
    self.assertEqual(l.comment, f'{pihole.phadlist.PHMARKER} {comment}')

    l.enabled = 'unknown'
    self.assertEqual(l.enabled, False)
    l.enabled = False
    self.assertEqual(l.enabled, False)

  def test_oneClient(self):
    comment="comment1"
    client="client1"
    group="Default,ads"
    c = OneClient(client=client, comment=comment, group=group)
    groups_id = [4, 8]
    c.groups_id = groups_id
    self.assertEqual(c.client, client)
    self.assertEqual(c.comment, f'{pihole.phadlist.PHMARKER} {comment}')
    self.assertEqual(c.groups, ["Default", "ads"])
    self.assertEqual(c.groups_id, groups_id)

  def test_oneDomain(self):
    domain = "mydomain"
    group = "default,test"
    comment = "Comment"
    type = 'deny'
    status = True
    d = OneDomain(domain=domain, groups=group, comment=comment, domaintype=type, status=str(status))
    groups_id = [4, 8]
    d.groups_id = groups_id
    self.assertEqual(d.domain, domain)
    self.assertEqual(d.comment, f'{pihole.phadlist.PHMARKER} {comment}')
    self.assertEqual(d.domaintype, type)
    self.assertEqual(d.groups, group.split(','))
    self.assertEqual(d.groups_id, groups_id)
    self.assertEqual(d.status, status)

    type = 'allow-regex'
    d.type = type
    self.assertEqual(d.domaintype, type)

    type = 'unknown'
    d.type = type
    self.assertEqual(d.domaintype, 'deny')

  def test_oneList(self):
    url = "myurl"
    groups = "default,test"
    comment = "Comment"
    type = 'allow'

    l = OneList(url=url, groups=groups, comment=comment, listtype=type)
    self.assertEqual(l.url, url)
    self.assertEqual(l.groups, groups.split(','))
    self.assertEqual(l.comment, f'{pihole.phadlist.PHMARKER} {comment}')
    self.assertEqual(l.listtype, type)

    l.listtype = 'unknown'
    self.assertEqual(l.listtype, 'block')
    l.listtype = 'block'
    self.assertEqual(l.listtype, 'block')


if __name__ == '__main__':
  unittest.main()
