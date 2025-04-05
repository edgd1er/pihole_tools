# pihole tools
tools to ease pihole.net administration

## phadlist.py

* load/erase lists according to the -f `<FILE>` through pihole's API.
* missing groups are created if needed.
* Lists added with this tools can be removed as a specific comment is add during creation.
* lists are loaded as block lists.

```bash
usage: phadlist.py [-h] [-a] [-c CONF] [-f FILE] [-r] [-R {all,mine,reset}] [-q] [-m] [-s] [-v]

manage lists through pihole API

options:
  -h, --help            show this help message and exit
  -a, --add             add or update lists found in <file>
  -c CONF, --conf CONF  read config <file>,load <param> section
  -f FILE, --file FILE  load lists from file
  -r, --replace         replace if possible groups and lists
  -R {all,mine,reset}, --remove {all,mine,reset}
                        remove lists: all, mine, reset
  -q, --quiet           if set to true, output error only
  -m, --mail            send mail even when not run by cron
  -s, --stats           send mail with statistics
  -v, --verbose         More output.
```

### configuration
phadlist.ini
```ini
[server1]
api_url = serverA.domain.tld
api_password = password1
```

list format:
```
#comment add to next list of no comment found in the line itself.
<url> group1,group2,groupe3,..... #possible comment
# firebog tick lists
https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt noAds,Default
.....
```

## loadCustom.py

insert into pihole.toml, hosts loaded from file named custom.list
A direct access to pihole.toml is required.

```
usage: loadCustom.py [-h] [-c] [-p] [-q] [-r] [-v] [-w]

merge custom list into pihole.toml

options:
-h, --help     show this help message and exit
-c, --custom   load custom.list and update hosts array.
-p, --ping     ping hosts from custom.list
-q, --quiet    if set to true, output error only
-r, --replace  if set to true, save to same file, otherwise save as basename_new.tom file
-v, --verbose  More output.
-w, --write    save modified file
```

custom.list format:
```bash
192.168.0.1   server1.domain.tld server2.domain.tld server3.domain.tld
```