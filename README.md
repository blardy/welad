WELAD (Windows Event Log Anomaly Detection)
============

Collection of scripts used for analysing Windows evtx logs - Anomaly detection scripts perform queries on elasticsearch database and export useful information (eg. suspicious logon, recreate process tree, suspicious services, suspicious change of time)


How to get started
--------

 + Logs should be ingest using winlogbeat - with the provided scripts (https://github.com/blardy/winlogbeat). If not you need to re-do mapping on `default.conf`
 + Update `default_conf.yml` with your Elasticsearch credentials. If you are not using the same Elasticsearch template, nor winlogbeat script; you need to re-create the mapping of fields.
 
```
TODO => requirements, install, conf ....
```
 
Help !! 
--------
Generic help:
```
usage: welad.py [-h] [--tag TAG] [-v {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                [-c CONF] [-o OUTPUT] [-w {console,csv}]
                {LogonHistory,RDPHistory,MaliciousPowerShell,BITSService,FailedLogonHistory,Search,ProcessTree,ProcessStat,LogonStat,SuspiciousProcess}
                ...

positional arguments:
  {LogonHistory,RDPHistory,MaliciousPowerShell,BITSService,FailedLogonHistory,Search,ProcessTree,ProcessStat,LogonStat,SuspiciousProcess}
                        Scenarios
    LogonHistory        Extract logon history
    RDPHistory          Extract logon history from LocalSessionManager logs
    MaliciousPowerShell
                        Search for malicious powershell in services /
                        powershell events
    BITSService         Abstract class for scenario using elasticsearch
    FailedLogonHistory  Extract logon history
    Search              Export events matching the given keyword
    ProcessTree         Rebuild process Tree
    ProcessStat         Prints stats about processes
    LogonStat           Print stats about logon
    SuspiciousProcess   Extract Suspicious processes

optional arguments:
  -h, --help            show this help message and exit
  --tag TAG             tag
  -v {DEBUG,INFO,WARNING,ERROR,CRITICAL}, --verbosity {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        increase output verbosity
  -c CONF, --conf CONF  conf file
  -o OUTPUT, --output OUTPUT
                        output file
  -w {console,csv}, --writer {console,csv}
                        writer to use
```

Each scenario can have specific additional arguments; example below with `ProcessTree`:
```
$> python3 welad.py  -c lab_conf.yml ProcessTree -h
usage: welad.py ProcessTree [-h] [--es_host ES_HOST] [--es_index ES_INDEX]
                            [--es_user ES_USER] [--es_password ES_PASSWORD]
                            [--system SYSTEM] [--from _FROM] [--to _TO]
                            [--filter FILTER] [--process_name PROCESS_NAME]
                            [--logon_id LOGON_ID] [--username USERNAME]
                            [--process_with_child_only]

optional arguments:
  -h, --help            show this help message and exit
  --es_host ES_HOST     IP:port of elasticsearch master
  --es_index ES_INDEX   elasticsearch index to query
  --es_user ES_USER
  --es_password ES_PASSWORD
  --system SYSTEM       Filter on system name (ie: plop-desktop)
  --from _FROM          YYYY-MM-DDTHH:MM:SS
  --to _TO              YYYY-MM-DDTHH:MM:SS
  --filter FILTER       Custom filter
                        "Event.EventData.Data.SubjectUserName.keyword:plop"
  --process_name PROCESS_NAME
                        Filter on field Event.EventData.Data.NewProcessName
                        (ie: powershell.exe)
  --logon_id LOGON_ID   Filter on logon Session ID (ie: 0x000000004e9f7608)
  --username USERNAME   Filter on logon username (ie: plop)
  --process_with_child_only
                        only prints processes that have childs
```

Example 
--------

Print processes per systems
```
$>  python3 welad.py  -c lab_conf.yml ProcessStat
_______________________________________________________________________________________________________________________
|      System      |     UserName     | Session ID | Nb Process |      First Process       |       Last Process       |
_______________________________________________________________________________________________________________________
|WRK-LAB-WIN10-02  |WRK-LAB-WIN10-0$  |0x3e7       |324         |2019-10-07T05:41:46.161Z  |2019-10-23T12:37:26.162Z  |
|WRK-LAB-WIN10-02  |WRK-LAB-WIN10-0$  |0x3e4       |3           |2019-10-23T12:34:37.610Z  |2019-10-23T12:34:38.938Z  |
|WRK-LAB-WIN10-02  |lardyba           |0x16c0b     |28          |2019-10-07T05:41:32.847Z  |2019-10-07T05:41:33.950Z  |
|WRK-LAB-WIN10-02  |lardyba           |0x17538     |10          |2019-10-23T12:34:23.990Z  |2019-10-23T12:36:16.843Z  |
|WRK-LAB-WIN10-02  |lardyba           |0x174e6     |7           |2019-10-23T12:36:22.271Z  |2019-10-23T12:37:13.595Z  |
|WRK-LAB-WIN10-02  |-                 |0x3e7       |11          |2019-10-23T12:34:08.848Z  |2019-10-23T12:34:14.247Z  |
|WRK-LAB-WIN10-02  |LOCAL SERVICE     |0x3e5       |1           |2019-10-23T12:36:17.923Z  |2019-10-23T12:36:17.923Z  |
_______________________________________________________________________________________________________________________
```

Re-create `lardyba` processes tree from 2019-10-23 (based on 4688 and 4689 events):
```
$> python3 welad.py  -c lab_conf.yml ProcessTree --username lardyba --from 2019-10-23
____________________________________________________________________________________________________________________________________________________________________________________________________________
|      System      |                 Process                 |    Date / Time (UTC)     |     username     |                                             Tree                                              |
____________________________________________________________________________________________________________________________________________________________________________________________________________
|WRK-LAB-WIN10-02  |C:\Windows\explorer.exe                  |2019-10-23T12:34:23.990Z  |lardyba           |C:\Windows\explorer.exe (pid: 3500; ppid:3464)                                                 |
|WRK-LAB-WIN10-02  |                                         |2019-10-23T12:34:44.225Z  |lardyba           |    \=> C:\Windows\System32\SecurityHealthSystray.exe (pid: 6204; ppid:3500)                   |
|WRK-LAB-WIN10-02  |                                         |2019-10-23T12:34:44.718Z  |lardyba           |    \=> C:\Windows\System32\vm3dservice.exe (pid: 6292; ppid:3500)                             |
|WRK-LAB-WIN10-02  |                                         |2019-10-23T12:34:45.206Z  |lardyba           |    \=> C:\Program Files\VMware\VMware Tools\vmtoolsd.exe (pid: 6364; ppid:3500)               |
|WRK-LAB-WIN10-02  |                                         |2019-10-23T12:34:47.916Z  |lardyba           |    \=> C:\Users\lardyba\AppData\Local\Microsoft\OneDrive\OneDrive.exe (pid: 6596; ppid:3500)  |
|WRK-LAB-WIN10-02  |                                         |2019-10-23T12:34:48.799Z  |lardyba           |    \=> C:\Windows\System32\cmd.exe (pid: 6632; ppid:3500)                                     |
|WRK-LAB-WIN10-02  |                                         |2019-10-23T12:34:48.980Z  |lardyba           |      \=> C:\Windows\System32\conhost.exe (pid: 6640; ppid:6632)                               |
|WRK-LAB-WIN10-02  |                                         |2019-10-23T12:36:16.763Z  |lardyba           |      \=> C:\Windows\System32\net.exe (pid: 5572; ppid:6632)                                   |
|WRK-LAB-WIN10-02  |                                         |2019-10-23T12:36:16.843Z  |lardyba           |        \=> C:\Windows\System32\net1.exe (pid: 3052; ppid:5572)                                |
|WRK-LAB-WIN10-02  |                                         |2019-10-23T12:36:22.160Z  |WRK-LAB-WIN10-0$  |    \=> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (pid: 6128; ppid:3500)       |
|WRK-LAB-WIN10-02  |C:\Windows\System32\MicrosoftEdgeSH.exe  |2019-10-23T12:34:36.417Z  |lardyba           |C:\Windows\System32\MicrosoftEdgeSH.exe (pid: 5852; ppid:5772)                                 |
|WRK-LAB-WIN10-02  |C:\Windows\System32\conhost.exe          |2019-10-23T12:36:22.271Z  |lardyba           |C:\Windows\System32\conhost.exe (pid: 6132; ppid:6128)                                         |
|WRK-LAB-WIN10-02  |C:\Windows\System32\net.exe              |2019-10-23T12:36:52.220Z  |lardyba           |C:\Windows\System32\net.exe (pid: 6040; ppid:6128)                                             |
|WRK-LAB-WIN10-02  |                                         |2019-10-23T12:36:52.229Z  |lardyba           |    \=> C:\Windows\System32\net1.exe (pid: 6052; ppid:6040)                                    |
|WRK-LAB-WIN10-02  |C:\Windows\System32\net.exe              |2019-10-23T12:37:03.616Z  |lardyba           |C:\Windows\System32\net.exe (pid: 6668; ppid:6128)                                             |
|WRK-LAB-WIN10-02  |                                         |2019-10-23T12:37:03.625Z  |lardyba           |    \=> C:\Windows\System32\net1.exe (pid: 5128; ppid:6668)                                    |
|WRK-LAB-WIN10-02  |C:\Windows\System32\net.exe              |2019-10-23T12:37:13.585Z  |lardyba           |C:\Windows\System32\net.exe (pid: 5976; ppid:6128)                                             |
|WRK-LAB-WIN10-02  |                                         |2019-10-23T12:37:13.595Z  |lardyba           |    \=> C:\Windows\System32\net1.exe (pid: 6092; ppid:5976)                                    |
____________________________________________________________________________________________________________________________________________________________________________________________________________
```

Print BITS URL foom system named `DESKTOP-IQDHTT1`:
```
$> python3 welad.py  -c lab_conf.yml BITSService --system DESKTOP-IQDHTT1
________________________________________________________________________
|  Computer Name  |     Location     | Path  | Params | Query | Nb Hits |
_________________________________________________________________________
|DESKTOP-IQDHTT1  |https://pastebin  |/plop  |        |       |1        |
_________________________________________________________________________
```

Print BITS URL in CSV format form system named `DESKTOP-IQDHTT1` and write output to `plop.csv`:
```
$> python3 welad.py -w csv -o plop.csv  -c lab_conf.yml BITSService --system DESKTOP-IQDHTT1
$> cat plop.csv
Computer Name|Location|Path|Params|Query|Nb Hits
DESKTOP-IQDHTT1|https://pastebin|/plop|||1
```

Todo / Roadmap 
--------
 - doc doc doc
 - 
