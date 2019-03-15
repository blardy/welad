WELAD (Windows Event Log Anomaly Detection)
============

Collection of scripts for EVTX ingest into ElasticSearch database and anomalies detection on Windows event logs.

Info
--------

Import tool (import_evtx_multi.py) is based on dgunter work (https://github.com/dgunter/evtxtoelk).
A few improvements / mofications were done:
  - Add arguments
    - destination index
    - file / folder
    - size of bulk
    - ElasticSearch user/password
    - metadata
  - Multiprocessing support
  - Normalize keys name as ES failed handling keys containing '@' and '#' chars
  - adding tag support

Anomaly detection scripts perform queries on elasticsearch database and export useful information (eg. suspicious logon)

Elastcisearch Configuration
--------
Depending on the amount of different event type inserted into a same EL index, you might want to increase the `total_fields.limit` of the index.
This operation can be performed with a `PUT` request to `_template/template_1`:

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

Update "index_patterns" with your index names.

Example (import_evtx_multi)
--------

Ingest a folder containing evtx files into `winevt-test` index:
```
python3 import_evtx_multi.py --folder /data/evtx/folder --es_index winevt-test --es_ip localhost
```

Ingest a single evtx file into `winevt-test` index:
```
python3 import_evtx_multi.py --file /data/evtx/folder/Security.evtx --es_index winevt-test --es_ip localhost
```

Ingest a folder containing evtx files into `winevt-test` index with adding a tag to each docs:
```
python3 import_evtx_multi.py --folder /data/evtx/folder --es_index winevt-test --es_ip localhost --tag CASE_NAME 
```

Ingest a folder containing evtx files into `winevt-test` index with adding a tag to each docs and metadatas (metadatas are only updated documents if it already exist):
```
python3 import_evtx_multi.py --folder /data/evtx/folder --es_index winevt-test --es_ip localhost --tag CASE_NAME --meta '{"batch_id" : "plop"}'
```

Ingest a folder containing evtx files into `winevt-test` index with message string resolution (see https://github.com/libyal/winevt-kb/wiki/Scripts for building the db)
```
python3 import_evtx_multi.py --folder /data/evtx/folder --es_index winevt-test --es_ip localhost -d /data/winevt-kb-db/winevt-kb.db
```

Example (welad)
--------
