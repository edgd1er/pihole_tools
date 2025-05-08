import unittest

from pihole.phadlist import OneClient, OneDomain, OneList


class TestOneXXInitAndMethods(unittest.TestCase):

  def test_oneClient(self):
    c = OneClient(client="client1", comment="comment1", group="Default,ads")
    groups_id = [4, 8]
    c.groups_id = groups_id
    self.assertEqual(c.client, "client1")
    self.assertEqual(c.comment, "comment1")
    self.assertEqual(c.groups, ["Default", "ads"])
    self.assertEqual(c.groups_id, groups_id)

  def test_oneDomain(self):
    domain = "mydomain"
    group = "default,test"
    comment = "Comment"
    type = 'deny'
    status = True
    d = OneDomain(domain=domain, groups=group, comment=comment, type=type, status=str(status))
    groups_id = [4, 8]
    d.groups_id = groups_id
    self.assertEqual(d.domain, domain)
    self.assertEqual(d.comment, comment)
    self.assertEqual(d.type, type)
    self.assertEqual(d.groups, group.split(','))
    self.assertEqual(d.groups_id, groups_id)
    self.assertEqual(d.status, status)

    type = 'allow-regex'
    d.type = type
    self.assertEqual(d.type, type)

    type = 'unknown'
    d.type = type
    self.assertEqual(d.type, 'deny')

  def test_oneList(self):
    url = "myurl"
    groups = "default,test"
    comment = "Comment"
    type = 'allow'

    l = OneList(url=url, groups=groups, comment=comment, type=type)
    self.assertEqual(l.url, url)
    self.assertEqual(l.groups, groups.split(','))
    self.assertEqual(l.comment, comment)
    self.assertEqual(l.type, type)

    l.type = 'unknown'
    self.assertEqual(l.type, 'block')
    l.type = 'block'
    self.assertEqual(l.type, 'block')


if __name__ == '__main__':
  unittest.main()
