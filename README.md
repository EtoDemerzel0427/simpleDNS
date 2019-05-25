# simpleDNS

## Overview

A simple but full-functioned DNS server, designed for the *Computer Networks* course this semester. Both `nslookup` on Windows/Linux and `dig` on Linux are supported(Tested already). You can also change your local DNS server to it, and surf the internet freely(Tested already). 

For the implementation,  it is actually a local DNS server and remote DNS relay. We store some local records in `json` format, if the domain you are looking up for is in the file, we simply get the answer locally.  If it is not, it will sent the query to another DNS server and when the response comes,  we answer the query and dynamically update the config file. The detailed documentation is on the way.



## Run

an example is as below:

```shell
python -m dnsrelay -d -autosave --server_ip xxx.xxx.xxx.xxx
```

For full information about the arguments, please use:

```shell
python -m dnsrelay -h
```



## Contributors

[@Weiran Huang](https://github.com/EtoDemerzel0427)

[@Zengrui Wang](https://github.com/Joeywzr)

[@Yuhao Lu](https://github.com/luyuhao98)