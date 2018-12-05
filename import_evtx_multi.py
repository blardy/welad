import contextlib
import mmap
import traceback
import json
import argparse
from collections import OrderedDict
from datetime import datetime

from glob import glob
from Evtx.Evtx import FileHeader
from Evtx.Views import evtx_file_xml_view
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
import xmltodict
import queue
import os
import uuid

import multiprocessing

from resolver.resolver import *


"""
    Q&D update of EvtxToElk package (https://dragos.com/blog/20180717EvtxToElk.html)
      => Add folder input instead of file
      => Add multiprocessing
      => normalize key name as ES has a hard time handling key containing @ and # chars
      => Added _id based on teh content of the event in order to avoid duplicate (when ingesting Shadow Copies...)
      => Added support for getting event description from winevt-kb database

    MIT License

    Copyright (c) 2018 Dan Gunter

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
"""


def _get_date(str_time):
    time_formats = ["%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"]
    time = None
    for time_format in time_formats:
        try:
            time = datetime.strptime(str_time, time_formats)
            if time:
                break
        except:
            pass

    return time



class CustomEvtxToElk:
    def _normalize(self, dictionnary):
        copy_dict = OrderedDict()
        for k,v in dictionnary.items():
            if isinstance(v, OrderedDict):
                copy_dict[k.replace('#','').replace('@','')] = self._normalize(v)
            else:
                copy_dict[k.replace('#','').replace('@','')] = v

        return copy_dict

    def evtx_to_elk(self, filename, tag, args, resolver):
        with open(filename) as infile:
            with contextlib.closing(mmap.mmap(infile.fileno(), 0, access=mmap.ACCESS_READ)) as buf:
                fh = FileHeader(buf, 0x0)
                data = ""
                try:
                    for xml, record in evtx_file_xml_view(fh):
                        try:
                            contains_event_data = False
                            log_line = xmltodict.parse(xml)

                            # Format the date field
                            date = log_line.get("Event").get("System").get("TimeCreated").get("@SystemTime")
                            if "." not in str(date):
                                date = datetime.strptime(date, "%Y-%m-%d %H:%M:%S")
                            else:
                                date = datetime.strptime(date, "%Y-%m-%d %H:%M:%S.%f")
                            log_line['@timestamp'] = str(date.isoformat())
                            log_line["Event"]["System"]["TimeCreated"]["@SystemTime"] = str(date.isoformat())

                            # BLA: remove special char (# & @) on key name
                            if log_line.get("Event"):
                                log_line["Event"] = self._normalize(log_line["Event"])

                            # Process the data field to be searchable
                            data = ""
                            if log_line.get("Event") is not None:
                                data = log_line.get("Event")
                                if log_line.get("Event").get("EventData") is not None:
                                    data = log_line.get("Event").get("EventData")
                                    if log_line.get("Event").get("EventData").get("Data") is not None:
                                        data = log_line.get("Event").get("EventData").get("Data")
                                        if isinstance(data, list):
                                            contains_event_data = True
                                            data_vals = {}
                                            for dataitem in data:
                                                try:
                                                    if dataitem.get("@Name") is not None:
                                                        data_vals[str(dataitem.get("@Name"))] = str(
                                                            str(dataitem.get("#text")))
                                                except:
                                                    pass
                                            log_line["Event"]["EventData"]["Data"] = data_vals
                                        else:
                                            if isinstance(data, OrderedDict):
                                                log_line["Event"]["EventData"]["RawData"] = json.dumps(data)
                                            else:
                                                log_line["Event"]["EventData"]["RawData"] = str(data)
                                            del log_line["Event"]["EventData"]["Data"]
                                    else:
                                        if isinstance(data, OrderedDict):
                                            log_line["Event"]["RawData"] = json.dumps(data)
                                        else:
                                            log_line["Event"]["RawData"] = str(data)
                                        del log_line["Event"]["EventData"]
                                else:
                                    if isinstance(data, OrderedDict):
                                        log_line = dict(data)
                                    else:
                                        log_line["RawData"] = str(data)
                                        del log_line["Event"]
                            else:
                                pass

                            # BLA: Adding Event key as some time it is removed ?!
                            if not log_line.get("Event", False):
                                new_dict = OrderedDict()
                                new_dict['Event'] = OrderedDict()
                                for k,v in log_line.items():
                                    if k == 'xmlns':
                                        new_dict[k] = v
                                    else:
                                        new_dict['Event'][k] = v
                                
                                log_line = new_dict
                            doc = json.loads(json.dumps(log_line))

                            # BLA - add info
                            if tag:
                                doc['tag'] = tag
                            if doc is not None and doc.get("Event", {}).get("EventData") is not None and doc.get("Event", {}).get("EventData", {}).get("Data", {}).get("OldTime", False) and log_line.get("Event", {}).get("EventData", {}).get("Data", {}).get("NewTime", False):
                                previous_time = _get_date(doc["Event"]["EventData"]["Data"]["OldTime"])
                                new_time = _get_date(doc["Event"]["EventData"]["Data"]["NewTime"])
                                if previous_time and new_time:
                                    doc["Event"]["EventData"]["Data"]["DeltaTime"] = (previous_time - new_time).total_seconds()


                            # TODO: shoudl load all the mysql db from into mem for perf...
                            if resolver:
                                description = resolver.get_message_string(doc["Event"]["System"]["Provider"]["Name"], int(doc["Event"]["System"]["EventID"]["text"]))
                                doc["Event"]["Description"] = {}
                                doc["Event"]["Description"]['raw'] = description
                                doc["Event"]["Description"]['full'] = description.replace('%n', '\n').replace('%r', '\r').replace('%t', '\t')
                                doc["Event"]["Description"]['short'] = description.strip().split('%n')[0]

                            doc["_id"] = str(uuid.uuid5(uuid.NAMESPACE_DNS, json.dumps(doc)))
                            
                            yield doc

                            # yield (idx, "winevt", json.loads(json.dumps(log_line)))
                            # es.index(index=idx, doc_type="winevt", body=json.loads(json.dumps(log_line)))
                        except GeneratorExit:
                            return
                        except:
                            print("***********")
                            print("Parsing Exception")
                            print(traceback.print_exc())
                            print(json.dumps(log_line, indent=2))
                            print("***********")
                except Exception as e:
                    print('{}: {}'.format(filename, e))

def worker(_id, elk_ip, elk_idx, l, tag, args):
    es = Elasticsearch([elk_ip], maxsize=128)
    resolver = None
    if args.database:
        resolver = Resolver(args.database)
    #print('[{}] Start worker with: {}'.format(_id, l))
    for evtx_file in l:
        print('  [{}] Start processing {}'.format(_id, evtx_file))
        try:
            bulk(es, CustomEvtxToElk().evtx_to_elk(evtx_file, tag, args, resolver), index=elk_idx, doc_type="winevt")
        except Exception as e:
            print(e)
            pass       

q = queue.Queue()

if __name__ == "__main__":
    # Create argument parser
    parser = argparse.ArgumentParser()
    # Add arguments
    parser.add_argument('--evtxfile', help="Evtx file to parse")
    parser.add_argument('--tag', help="tag")
    parser.add_argument('--evtxfolder', help="Evtx folder")
    parser.add_argument('--elk_ip', default="localhost", help="IP (and port) of ELK instance")
    parser.add_argument('--elk_index', default="default", help="IP (and port) of ELK instance")
    parser.add_argument('--thread', type=int, default=4, help="IP (and port) of ELK instance")

    parser.add_argument('-d', '--database', required=False, help='Main winevt-kb database')

    # Parse arguments and call evtx to elk class
    args = parser.parse_args()

    idx = 'winevt-{}'.format(args.elk_index.lower())
    threads = []
    if args.evtxfile:
        evtx_files = [args.evtxfile]
    elif args.evtxfolder:
        evtx_files = [ y for x in os.walk(args.evtxfolder) for y in glob(os.path.join(x[0], '*.evtx'))]

    thread_info = {}
    for thread_id in range(0,args.thread):
        thread_info[thread_id] = {
            'files' : [],
            'files_size' : 0
        }
    # get thread with min list
    def get_thread_with_smallest_size(thread_info):
        thread_id_with_smallest_size = 0
        for thread_id, thread_data in thread_info.items():
            if thread_data['files_size'] < thread_info[thread_id_with_smallest_size]['files_size']:
                thread_id_with_smallest_size = thread_id

        return thread_id_with_smallest_size


    for evtx_file in evtx_files:
        thread_id = get_thread_with_smallest_size(thread_info)
        thread_info[thread_id]['files'].append(evtx_file)
        thread_info[thread_id]['files_size'] += os.stat(evtx_file).st_size
        
    for thread_id, thread_data in thread_info.items():
        print('[{}] Having {} files for a size of {}'.format(thread_id, len(thread_data['files']), thread_data['files_size'] ))

    lists = [ thread_data['files'] for thread_id, thread_data in thread_info.items()]


    jobs = []
    for i in range(args.thread):
        p = multiprocessing.Process(target=worker, args=(i, args.elk_ip, idx, lists[i], args.tag, args))
        jobs.append(p)
        p.start()
