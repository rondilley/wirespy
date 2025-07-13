# WireSpy (wsd)

by Ron Dilley <ron.dilley@uberadmin.com>

You can find the latest information on wirespy [here](http://www.uberadmin.com/Projects/wsd/ "WireSpy")

## What is WireSpy (wsd)?

Wirespy is a simple network sniffer for information security that extracts
interesting metadata about network traffic and logs it.  That sounds like
a million other security and network tools, and it is in many ways though
there are some very important differences.

## Why use it?

Wirespy is not a replacement for tcpdump, wireshark or any of the other
network sniffers.  It has a specific purpose in providing long term
metadata about network traffic including TCP flow logging.  It is efficent
and can monitoring live network traffic or process PCAP files.

I use it on my network recorders to extract metadata from the PCAP files
that takes up less space, further extended the number of months of network
intelligence I can save before running out of disk space.

The TCP flow capability is tollerant of lost packets which are common
when passively monitoring network traffic.

## Implementation

Wirespy can run as a daemon if you are using it to monitor live network
traffic and can also process PCAP files saved using other tools that support
libpcap format files.

Below are the options that wirespy supports.

```
wsd v0.8 [Jul 13 2025 - 11:27:41]

syntax: wsd [options]
 -c|--chroot {dir}    chroot into directory
 -d|--debug (0-9)     enable debugging info
 -g|--group {group}   run as an alternate group
 -h|--help            this info
 -i|--iniface {int}   specify interface to listen on
 -l|--logdir {dir}    directory to create logs in (default: /var/log/wsd)
 -L|--logfile {fname} specify log file instead of dynamic generated filenames
 -p|--pidfile {fname} specify pid file (default: /var/run/wsd.pid)
 -r|--read {fname}    specify pcap file to read
 -R|--rflow {fname}   specify flow cache file to read
 -u|--user {user}     run as an alernate user
 -v|--version         display version information
 -V|--verbose         log additional details about traffic
 -W|--wflow {fname}   specify flow cache file to write
```

Starting wirespy from the command line with no arguments will cause the tool
to locate the first network interface and begin monitoring and logging in the
background.

```sh
% sudo ./wsd
wsd v0.6 [Jan  3 2018 - 18:00:21] starting in daemon mode
```

You can also specify the interface to monitor using the -i|--iniface command line switch.

```sh
% sudo ./wsd -i eth0
```

When wirespy runs in the background, it creates log files in a directory specified
on the command line.  The default is "/var/log/wsd" and the files are created
dynamically using the hostname of the machine and a time/date stamp.

{hostname}_{year}{month}{day}_{hour}{minute}{second}.log, (e.g. ubuntu-dev_20180102_235305.log).

You can specify an alternate directory to store the logs using the -l|--logdir command line switch.

```sh
% sudo ./wsd -l /var/log/wirespy -i eth0
```

By detault, wirespy logs TCP flow logs are new-line separated records starting with "TCPFLOW" and using key=value pairs.

Below is an example of TCPFLOW logs:

```
TCPFLOW startTime=2018/01/03 16:37:57 sourceMac=10:c3:7b:9b:41:c9 sourceIp=172.20.1.144 sourcePort=65087 destMac=8:5b:e:6d:14:e8 destIp=172.20.1.3 destPort=8013 duration=0 packetsIn=1 packetsOut=4 bytesIn=32 bytesOut=92
TCPFLOW startTime=2018/01/03 16:37:57 sourceMac=10:c3:7b:9b:41:c9 sourceIp=172.20.1.144 sourcePort=65088 destMac=8:5b:e:6d:14:e8 destIp=172.20.1.3 destPort=8013 duration=1 packetsIn=7 packetsOut=9 bytesIn=520 bytesOut=2104
TCPFLOW startTime=2018/01/03 16:38:03 sourceMac=0:1a:62:3:f4:fd sourceIp=172.20.1.157 sourcePort=42852 destMac=10:c3:7b:9b:41:c9 destIp=172.20.1.144 destPort=49168 duration=0 packetsIn=1 packetsOut=5 bytesIn=40 bytesOut=462
TCPFLOW startTime=2018/01/03 16:38:04 sourceMac=10:c3:7b:9b:41:c9 sourceIp=172.20.1.144 sourcePort=65090 destMac=8:5b:e:6d:14:e8 destIp=77.72.116.213 destPort=80 duration=1 packetsIn=2 packetsOut=6 bytesIn=44 bytesOut=1290
TCPFLOW startTime=2018/01/03 16:36:36 sourceMac=10:c3:7b:9b:41:c9 sourceIp=172.20.1.144 sourcePort=65043 destMac=8:5b:e:6d:14:e8 destIp=157.240.11.22 destPort=443 duration=89 packetsIn=667 packetsOut=760 bytesIn=1664038 bytesOut=27407
```

If you use the -V|--verbose command line switch, wirespy will also log metadata
about each packet.

The time/date is stored as an seconds from the epoc and microseconds.  Next is
the source and destination MAC addresses, then source IP/port, flow direction
and destination IP/port.

TCP packets include the bit flags as follows:

| label | flag  |
| -----:| ----- |
|F | FIN |
|S | SYN |
|R | RESET |
|P | PUSH |
|A | ACK |
|U | URG |
|E | ECE (Not all operating systems support this) |
|C | CWR (Not all operating systems support this) |

TCP packets also include TCP windows and sequence/acknoledgement information.

```
[1515026248.684504] 10:c3:7b:9b:41:c9->8:5b:e:6d:14:e8       172.20.1.144:58410 ->    192.168.10.20:53    UDP
[1515026248.712000] e8:50:8b:8a:17:72->1:0:5e:0:0:fb         172.20.1.110:5353  ->      224.0.0.251:5353  UDP
[1515026248.734846] 10:c3:7b:9b:41:c9->8:5b:e:6d:14:e8       172.20.1.144:64950 ->    23.72.109.149:443   TCP [..R.A.] win: 0 seq: 2444018074 (+907) ack: 1890184749 (+4364)
[1515026248.735153]   8:5b:e:6d:14:e8->10:c3:7b:9b:41:c9    23.72.109.149:443   ??     172.20.1.144:64950 TCP [F...A.] win: 983 seq: 1890184749 (+0) ack: 2444018074 (+0)
[1515026248.944796]   8:5b:e:6d:14:e8->10:c3:7b:9b:41:c9    192.168.10.20:53    ->     172.20.1.144:58410 UDP
[1515026248.946232] 10:c3:7b:9b:41:c9->8:5b:e:6d:14:e8       172.20.1.144:65085 ->    23.72.109.149:443   TCP [.S....] win: 8192 seq: 2704739502 (+0) ack: 0          (+0)
[1515026248.970288]   8:5b:e:6d:14:e8->10:c3:7b:9b:41:c9    23.72.109.149:443   <-     172.20.1.144:65085 TCP [.S..A.] win: 29200 seq: 1911183577 (+0) ack: 2704739503 (+1)
[1515026248.970290] 10:c3:7b:9b:41:c9->8:5b:e:6d:14:e8       172.20.1.144:65085 ->    23.72.109.149:443   TCP [....A.] win: 16425 seq: 2704739503 (+1) ack: 1911183578 (+1)
[1515026248.970513] 10:c3:7b:9b:41:c9->8:5b:e:6d:14:e8       172.20.1.144:65085 ->    23.72.109.149:443   TCP [...PA.] win: 16425 seq: 2704739503 (+1) ack: 1911183578 (+1)
[1515026248.993625]   8:5b:e:6d:14:e8->10:c3:7b:9b:41:c9    23.72.109.149:443   <-     172.20.1.144:65085 TCP [....A.] win: 946 seq: 1911183578 (+1) ack: 2704740020 (+518)
[1515026248.997441]   8:5b:e:6d:14:e8->10:c3:7b:9b:41:c9    23.72.109.149:443   <-     172.20.1.144:65085 TCP [...PA.] win: 946 seq: 1911183578 (+1) ack: 2704740020 (+518)
[1515026248.997582] 10:c3:7b:9b:41:c9->8:5b:e:6d:14:e8       172.20.1.144:65085 ->    23.72.109.149:443   TCP [...PA.] win: 16387 seq: 2704740020 (+518) ack: 1911183730 (+153)
[1515026249.008646] 10:c3:7b:9b:41:c9->8:5b:e:6d:14:e8       172.20.1.144:65085 ->    23.72.109.149:443   TCP [...PA.] win: 16387 seq: 2704740071 (+569) ack: 1911183730 (+153)
[1515026249.021507]   8:5b:e:6d:14:e8->10:c3:7b:9b:41:c9    23.72.109.149:443   <-     172.20.1.144:65085 TCP [....A.] win: 983 seq: 1911183730 (+153) ack: 2704740658 (+1156)
[1515026249.088904]   8:5b:e:6d:14:e8->10:c3:7b:9b:41:c9    23.72.109.149:443   <-     172.20.1.144:65085 TCP [...PA.] win: 983 seq: 1911183730 (+153) ack: 2704740658 (+1156)
[1515026249.088910]   8:5b:e:6d:14:e8->10:c3:7b:9b:41:c9    23.72.109.149:443   <-     172.20.1.144:65085 TCP [...PA.] win: 983 seq: 1911184068 (+491) ack: 2704740658 (+1156)
[1515026249.088911] 10:c3:7b:9b:41:c9->8:5b:e:6d:14:e8       172.20.1.144:65085 ->    23.72.109.149:443   TCP [....A.] win: 16268 seq: 2704740658 (+1156) ack: 1911184205 (+628)
[1515026249.681525] 10:c3:7b:9b:41:c9->8:5b:e:6d:14:e8       172.20.1.144:64882 ->    54.69.171.226:443   TCP [...PA.] win: 16330 seq: 3483410318 (+5822) ack: 668567418  (+19721)
[1515026249.724897]   8:5b:e:6d:14:e8->10:c3:7b:9b:41:c9    54.69.171.226:443   <-     172.20.1.144:64882 TCP [....A.] win: 79 seq: 668567418  (+19721) ack: 3483410397 (+5901)
[1515026252.251586] 10:c3:7b:9b:41:c9->ff:ff:ff:ff:ff:ff     172.20.1.144:62656 ->     172.20.1.255:5002  UDP
[1515026252.685247] 10:c3:7b:9b:41:c9->8:5b:e:6d:14:e8       172.20.1.144:65081 ->    77.72.116.213:443   TCP [F...A.] win: 64240 seq: 414071950  (+1) ack: 2072829561 (+1)
[1515026252.685455] 10:c3:7b:9b:41:c9->8:5b:e:6d:14:e8       172.20.1.144:65072 ->    212.58.246.90:80    TCP [..R.A.] win: 0 seq: 2660565370 (+852) ack: 96094891   (+292)
[1515026252.685704] 10:c3:7b:9b:41:c9->8:5b:e:6d:14:e8       172.20.1.144:65074 ->    212.58.246.90:80    TCP [..R.A.] win: 0 seq: 3685576952 (+783) ack: 1800050690 (+110)
[1515026252.686813] 10:c3:7b:9b:41:c9->8:5b:e:6d:14:e8       172.20.1.144:65079 ->   23.215.100.184:80    TCP [...PA.] win: 16425 seq: 1334548897 (+1106) ack: 457911392  (+3728)
[1515026252.704476]   8:5b:e:6d:14:e8->10:c3:7b:9b:41:c9   23.215.100.184:80    <-     172.20.1.144:65079 TCP [...PA.] win: 1047 seq: 457911392  (+3728) ack: 1334549270 (+1479)
[1515026252.856904] 10:c3:7b:9b:41:c9->8:5b:e:6d:14:e8       172.20.1.144:65081 ->    77.72.116.213:443   TCP [....A.] win: 64240 seq: 414071951  (+2) ack: 2072829562 (+2)
[1515026252.904309] 10:c3:7b:9b:41:c9->8:5b:e:6d:14:e8       172.20.1.144:65079 ->   23.215.100.184:80    TCP [....A.] win: 16165 seq: 1334549270 (+1479) ack: 457912432  (+4768)
[1515026253.017380]   8:5b:e:6d:14:e8->10:c3:7b:9b:41:c9  173.194.203.189:443   ->     172.20.1.144:55599 UDP
```

One of the interesting and handy features of wirespy is the ability to save the current TCP flow data to a file and read it back in for a subsequent wirespy run.  This allows
you to run wirespy on a series of PCAP files while maintaining TCP flow coherency across multiple executions of wirespy.

I use this feature with my packet vacuum to post-process PCAP files.

```sh
% sudo ./wsd -R /var/log/wsd/wsd.cache -W /var/log/wsd/wsd.cache -r ./20180103181536.889275-sensor01.trunk0.pcap
```

Each time you run wirespy, it will read the flow cache from the previous run and after processing the PCAP file,
wirespy will save the updated flow cache.

When you use wirespy to read PCAP files, you can use the -L|--logfile command line switch to specify where to write
the log data instead of storing it in a directory using a generated filename.

This is how I post-process PCAP files on my packet vacuum:

Where ${tfile} is the pcap filename+pid and ${file} is just the pcap filename.  The sort orders
the pcap files oldest to newest based on the date/time in the filenames.

```sh
for tfile in `/usr/bin/find /var/twt/data -type f -name "*.pcap.${PID}" | sort -k29,49 -n`; do
 /usr/local/bin/wsd -R /var/run/wsd.cache -W /var/run/wsd.cache -V -r ${tfile} -L ${file}.wsd
```

You may have noticed another tool in the distribution called flowcache.  I will be adding
functionality to this as a way to extract useful information directly from the flow cache
file without running wirespy.

## Security Implications

Assume that there are errors in the wsd source that
would allow a specially crafted packet to allow an attacker
to exploit wsd to gain access to the computer that wsd is
running on!!!  wsd tries to get rid of priviledges it does
not need and can run in a chroot environment.  I recommend
that you use the chroot and uid/gid options.  They are there
to compensate for my poor programming skills.  Don't trust
this software and install and use is at your own risk.

## Bugs

I am not a programmer by any stretch of the imagination.  I
have attempted to remove the obvious bugs and other
programmer related errors but please keep in mind the first
sentence.  If you find an issue with code, please send me
an e-mail with details and I will be happy to look into
it.

Ron Dilley
ron.dilley@uberadmin.com
