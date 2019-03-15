#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    Ingest EVTX file(s) into an ElasticSearch database
       Based on Dan Gunter work (https://dragos.com/blog/20180717EvtxToElk.html)
"""
__progname__ = "Import EVTX (multi)"
__version__ = "0.1"


import logging
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
import os
import uuid

import multiprocessing

from resolver.resolver import *

LOG_FORMAT = '[%(asctime)s][{}][{}][%(levelname)s]%(funcName)s:'.format(__progname__, __version__) + ' %(message)s'
LOG_VERBOSITY = {
    'DEBUG' : logging.DEBUG,
    'INFO' : logging.INFO,
    'WARNING' : logging.WARNING,
    'ERROR' : logging.ERROR,
    'CRITICAL' : logging.CRITICAL,
}


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


def _get_date(str_time, time_formats = ["%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"]):
    """ converts teh given string to a datetime using the given format strings
    """
    time = None
    for time_format in time_formats:
        try:
            time = datetime.strptime(str_time, time_format)
            if time:
                break
        except:
            pass
    return time


class CustomEvtxToElk:
    def _normalize(self, dictionnary):
        """ Removes '#' or '@' in keys of the given dict
        """
        copy_dict = OrderedDict()
        for k,v in dictionnary.items():
            if isinstance(v, OrderedDict):
                copy_dict[k.replace('#','').replace('@','')] = self._normalize(v)
            else:
                copy_dict[k.replace('#','').replace('@','')] = v
        return copy_dict

    def evtx_to_elk(self, filename, tag, args, resolver, metadata):
        with open(filename) as infile:
            with contextlib.closing(mmap.mmap(infile.fileno(), 0, access=mmap.ACCESS_READ)) as buf:
                fh = FileHeader(buf, 0x0)
                data = ""
                try:
                    for xml, record in evtx_file_xml_view(fh):
                        try:
                            contains_event_data = False
                            log_line = xmltodict.parse(xml)

                            # Convert to datetime
                            date = _get_date(log_line.get("Event").get("System").get("TimeCreated").get("@SystemTime"))
                            str_date = str(date.isoformat())
                            log_line['@timestamp'] = str_date
                            log_line["Event"]["System"]["TimeCreated"]["@SystemTime"] = str_date

                            # Remove weird chars in keys
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
                                                    if dataitem.get("Name") is not None:
                                                        data_vals[str(dataitem.get("Name"))] = str(
                                                            str(dataitem.get("text")))

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


                            # TODO: should load all the mysql db from into mem for perf...
                            doc["Event"]["Description"] = {}
                            doc["Event"]["Description"]['raw'] = ''
                            doc["Event"]["Description"]['full'] = ''
                            doc["Event"]["Description"]['short'] = ''
                            if resolver:
                                description = resolver.get_message_string(doc["Event"]["System"]["Provider"]["Name"], int(doc["Event"]["System"]["EventID"]["text"]))
                                doc["Event"]["Description"]['raw'] = description
                                doc["Event"]["Description"]['full'] = description.replace('%n', '\n').replace('%r', '\r').replace('%t', '\t')
                                doc["Event"]["Description"]['short'] = doc["Event"]["Description"]['full'].strip().split('\n')[0]

                            doc["_id"] = str(uuid.uuid5(uuid.NAMESPACE_DNS, json.dumps(doc)))
                            # Avoid duplicate
                            doc.update(metadata)

                            
                            yield doc

                        except GeneratorExit:
                            return
                        except:
                            logging.error("***********")
                            logging.error("Parsing Exception")
                            logging.error(traceback.print_exc())
                            logging.error(json.dumps(log_line, indent=2))
                            logging.error("***********")
                except Exception as e:
                    logging.error('{}: {}'.format(filename, e))

def ingest_worker(worker_id, es_ip, es_idx, files, tag, args):
    logging.warning('Start worker [{}] with {} files to ingest'.format(worker_id, len(files)))

    es = Elasticsearch([es_ip], maxsize=128, timeout=120, max_retries=10, retry_on_timeout=True, http_auth=(args.es_user, args.es_password))
    resolver = None
    if args.database:
        resolver = Resolver(args.database)

    for evtx_file in files:
        logging.warning('  [{}] Start processing {}'.format(worker_id, evtx_file))
        try:
            metadata = args.meta
            metadata['filename'] = evtx_file
            bulk(es, CustomEvtxToElk().evtx_to_elk(evtx_file, tag, args, resolver, metadata), index=es_idx, doc_type="winevt", chunk_size=args.bulk_size) #, request_timeout=60
        except Exception as e:
            logging.error(e)
            pass       

    logging.warning('End worker [{}]'.format(worker_id))
    return True



def list_files(file, folder, extension = '*.evtx'):
    """ It returns a list of files based on teh given input path and filter on extension
    """
    if file:
        return [file]
    elif folder:
        return [ y for x in os.walk(folder) for y in glob(os.path.join(x[0], extension))]
    else:
        return []


def dispatch_files_bysize(nb_list, files):
    """ It creates N list of files based on filesize to average the size between lists.
    """

    logging.info('Having {} files to dispatch in {} lists'.format(len(files), nb_list))
    #
    #  1 - Init N lists of size 0.
    #
    sublists = {}
    for list_id in range(0,nb_list):
        sublists[list_id] = {
            'files' : [],
            'size' : 0
        }

    #
    #  2 - For each file, get the smallest sublist and append file.
    #

    def _get_smallest_sublist(sublists):
        """ get the smallest sublist
        """
        smallest_list_id = 0
        for list_id, sublist in sublists.items():
            if sublist['size'] < sublists[smallest_list_id]['size']:
                smallest_list_id = list_id

        return smallest_list_id

    for file in files:
        logging.info('dispatching {}'.format(file))
        list_id = _get_smallest_sublist(sublists)
        sublists[list_id]['files'].append(file)
        sublists[list_id]['size'] += os.stat(file).st_size
        
    for list_id, sublist in sublists.items():
        logging.warning(' List [{}] Having {} files for a size of {}'.format(list_id, len(sublist['files']), sublist['size'] ))

    return [ sublist['files'] for list_id, sublist in sublists.items()]

def import_evtx():
    #
    # 1 - Parse arguments
    #
    parser = argparse.ArgumentParser()   
    parser.add_argument("-v", "--verbosity", help="increase output verbosity", choices = LOG_VERBOSITY, default='WARNING')

    parser.add_argument('--file', help="Evtx file to parse")
    parser.add_argument('--folder', help="Evtx folder to parse")

    parser.add_argument('--tag', help="tag the inserted event, 2 identical events with different tags will create 2 distinct documents, if you want to de-duplicate events use --meta")
    parser.add_argument('--meta', type=json.loads, default={}, help="JSON metadata to add (if duplicate veent, it will update doc)")

    parser.add_argument('--nb_process', type=int, default=4, help="Number of Ingest processes to spawn, only useful for more than 1 file")
    parser.add_argument('--bulk_size', type=int, default=750, help="BUlk size to use when sending docs into ElasticSearch")

    
    parser.add_argument('--es_ip', default="localhost", help="IP (and port) of ELK instance")
    parser.add_argument('--es_index', default="winevt-lab", help="index to use for ingest process")
    parser.add_argument('--es_user', default='elastic', help="User for ES instance")
    parser.add_argument('--es_password', default='', help="Password for ES instance")

    parser.add_argument('-d', '--database', required=False, help='Main winevt-kb database for resolving event description string based on channel/eventID')

    args = parser.parse_args()

    logging.basicConfig(format=LOG_FORMAT, level=LOG_VERBOSITY[args.verbosity], datefmt='%Y-%m-%d %I:%M:%S')

    # 
    # 2 - Get Files & dispatch them into lists for multiprocessing puprose
    #
    evtx_files = list_files(args.file, args.folder, extension = '*.evtx')
    if not evtx_files:
        logging.error('Missing either --file or --folder arguments, or directory does not contain valid files...')
        return

    #
    # 3 - Dispatch files into a list for each process
    #         [ [list1], [list2], [list3], [list4], ....]
    # TODO: should use a multiprocessing.Pipe or Queue instead...
    sublists = dispatch_files_bysize(args.nb_process, evtx_files)

    #
    # 4 - Create N Ingestion process 
    #

    with multiprocessing.Pool(processes=args.nb_process) as pool:
        results =  []
        for process_id in range(args.nb_process):
            results.append(pool.apply_async(ingest_worker, args=(process_id, args.es_ip, args.es_index.lower(), sublists[process_id], args.tag, args)))

        [res.get() for res in results]

if __name__ == "__main__":
    import_evtx()
