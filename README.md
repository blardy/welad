WELAD (Windows Event Log Anomaly Detection)
============

TODO

Info
--------

TODO
Anomaly detection scripts perform queries on elasticsearch database and export useful information (eg. suspicious logon)

Elasticsearch Configuration
--------

TODO => curl for the template
 + Logs should be ingest using winlogbeat - with the provided scripts => link to winlogbeat repo

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

How to get started
--------

TOOD => requirements, install, conf ....

Example 
--------

todo
```
todo
```

Todo / Roadmap 
--------
 - rebuild code for automatic nested field extraction based on field name (plop.plip.ploup.field), so mapping can be changed anytime :)
 - doc
 - 
