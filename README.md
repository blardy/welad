WELAD (Windows Event Log Anomaly Detection)
============

TODO

Info
--------

TODO
Anomaly detection scripts perform queries on elasticsearch database and export useful information (eg. suspicious logon)

Elasticsearch Configuration
--------

 + Logs should be ingest using winlogbeat - with the provided scripts (https://github.com/blardy/winlogbeat). If not you need to re-do mapping on `default.conf`
 

How to get started
--------

TOOD => requirements, install, conf ....

Example 
--------

Re-create process tree based on 4688 and 4689 events:
```
$> python3 welad.py  -c lab_conf.yml ProcessTree --username lardyba --from 2019-10-23
[2019-11-22 04:20:41][Welad][0.1][WARNING]main: Hello hello....
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
[2019-11-22 04:20:41][Welad][0.1][WARNING]main: Bye bye....
```

Todo / Roadmap 
--------
 - doc doc doc
 - 
