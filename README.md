WELAD (Windows Event Log Anomaly Detection)
============

Collection of scripts for anomalies detection on Windows event logs.

Info
--------

Import tool (import_evtx_multi.py) is based on dgunter work (https://github.com/dgunter/evtxtoelk).
A few improvment / mofication was done:
  - Add argument for destination index
  - Add argument for input (handle folder and file)
  - Multiprocessing support
  - Normalize keys name as ES failed handling keys containing '@' and '#' chars
  - adding tag support

Anomaly detection scripts perform queries on elasticsearch database and export useful information (eg. suspicious logon)

Dependancies
--------

TODO
```
TODO
```

Configuration
--------
Depending on the amount of different event type inserted into a same EL index, you might want to increase the `total_fields.limit` of the index.
This operation can be performed with a `PUT` request to `_template/<TEMPLATE_NAME>`:

```
PUT _template/template_1
{
  "order": 0,
  "version": 60001,
  "index_patterns": [
    "winevt-*"
  ],
  "settings": {
    "index": {
      "mapping": {
        "total_fields": {
          "limit": "9999"
        }
      },
      "refresh_interval": "5s",
      "number_of_replicas": "0"
    }
  }
}
```

Example
--------

Ingest a folder containing evtx files into `winevt-test` index:
```
 python3 parse_evtx_custom.py --elk_ip localhost --elk_index test --evtxfolder /data/evtx/folder
```

Ingest a single evtx file into `winevt-test` index:
```
 python3 parse_evtx_custom.py --elk_ip localhost --elk_index test --evtxfile /data/evtx/folder/Security.evtx
```

TODO: anomaly detection example
