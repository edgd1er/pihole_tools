# pihole tools
tools to ease pihole.net administration

## phadlist.py

* load/erase lists according to the -f `<FILE>` through pihole's API.
* missing groups are created if needed.
* Lists added with this tools can be removed as a specific comment is add during creation.
* lists are loaded as block lists.

```bash
usage: phadlist.py [-h] [-c CONF] [-l <file>] [-L {all,mine,reset}] [-d <file>] [-D {all,mine,reset}] [-k <file>] [-K <file>] [-r] [-q] [-m] [-s] [-v]

manage lists and domains through pihole API

options:
  -h, --help            show this help message and exit
  -l FILE, --lists FILE load lists found in <file>
  -L {all,mine,reset}, --remove_lists {all,mine,reset}
                        remove lists: all, mine, reset
  -k FILE, --clients FILE        load clients found in <file>
  -K {all,mine,reset}, --remove_clients {all,mine,reset}
                        load clients found in <file>
  -d FILE, --domains FILE
                        load domain found in <file>
  -D {all,mine,reset}, --remove_domains {all,mine,reset}
                        remove domains: all, mine, reset
  -c CONF, --conf CONF  read config <file>,load <param> section
  -r, --replace         replace if possible groups and lists
  -q, --quiet           if set to true, output error only
  -m, --mail            send mail even when not run by cron
  -s, --stats           send mail with statistics
  -v, --verbose         More output.
```

### Configuration
#### phadlist.ini
```ini
[server1]
api_url = serverA.domain.tld
api_password = password1
```

#### list format:
add, delete (all, mine, reset) urls to block or allow
```
#comment add to next list of no comment found in the line itself.
<url> group1,group2,groupe3,..... #possible comment
# firebog tick lists
https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt noAds,Default
.....
```

#### domain format:
add, delete (all, mine) domains to block or allow
```
<domain with wildcard|domain regex> <groups separated with a comma> <allow|allow-regex|deny|deny-regex> #any comment (optional)
# if a line comment is found, it will used as default comment unless a comment is found in the structure.
cdn.ravenjs.com allow Default #whitelist ravenjs
(\.|^)wakanim\.tv$ deny-regex group1 #Wakanim block
```

#### Suggested procedure to export, delete and import all sqlite contents.

please backup you .db files, you may need them if ever this procedure fails.

* Export all items
```bash
for i in groups clients domains lists; do ./phadlist.py -c <target_dns> -e ${i}; done 
```
* Delete all items (all, mine or reset). groups has to be the last to be deleted to keep structure integrity.
```bash
for i in K D L G; do ./phadlist.py -c <target_dns> -${i} mine; done 
```
* Import items in that order
```bash
#load groups.list and import data
./phadlist.py -c <target_dns> -u groups -x
#load clients.list and import data
./phadlist.py -c <target_dns> -c clients -x
# .list domains.list and import data
./phadlist.py -c <target_dns> -d domains -x
# .load list.list and import data
./phadlist.py -c <target_dns> -l lists -x
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