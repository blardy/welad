#!/usr/bin/env python
# -*- coding: utf-8 -*-

__progname__ = 'resolver'

import logging
import argparse
import sqlite3


LOG_FORMAT = '[%(asctime)s][{}][%(levelname)s]%(funcName)s:'.format(__progname__) + ' %(message)s'
LOG_VERBOSITY = {
    'DEBUG' : logging.DEBUG,
    'INFO' : logging.INFO,
    'WARNING' : logging.WARNING,
    'ERROR' : logging.ERROR,
    'CRITICAL' : logging.CRITICAL,
}

winevt_db = None

class Resolver(object):
    """docstring for Resolver"""
    def __init__(self, database):
        self.database = database

        self.filename = database.split('/')[-1]
        self.basename = './'
        if len(database.split('/')[-1]) > 1:
            self.basename = '/'.join(database.split('/')[:-1])
            self.basename += '/'

        self.database_conn = sqlite3.connect(database)

        self.database_cache_connectors = {
            database : self.database_conn
        }

    def __del__(self):
        for database, database_conn in self.database_cache_connectors.items():
            database_conn.close()


    def open_db(self, database):
        """ Get a connection to the db from cache, open it otherwise.
        """
        conn = self.database_cache_connectors.get(database, False)
        if not conn:
            conn = sqlite3.connect(database)
            self.database_cache_connectors[database] = conn

        return conn

    def get_message_string(self, provider, eventid, lcid = 0x409, vers= 'IDontCareAboutThis...'):
        try:
            main_db = self.open_db(self.database)

            QUERY_PROVIDER_DB = """
            SELECT database_filename FROM event_log_providers 
                INNER JOIN message_file_per_event_log_provider ON 
                    message_file_per_event_log_provider.event_log_provider_key = event_log_providers.event_log_provider_key
                INNER JOIN message_files ON 
                    message_files.message_file_key = message_file_per_event_log_provider.message_file_key 
            WHERE log_source=?
            """
            database_filename = main_db.execute(QUERY_PROVIDER_DB, (provider,)).fetchone()
            if not database_filename:
                return ""
            else:
                database_filename = database_filename[0]

            database_filename = self.basename + database_filename
            provider_db = self.open_db(database_filename)
            cursor = provider_db.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [table[0] for table in cursor.fetchall() if 'message_table_0x' in table[0]]

            try:
                table_name = 'message_table_0x{:08x}{}'.format(lcid, vers)
                str_eventid = '%{:05x}'.format(eventid)
                QUERY_EVENT_MESS = "SELECT message_string FROM {} WHERE message_identifier like ?".format(table_name)
                message = provider_db.execute(QUERY_EVENT_MESS, (str_eventid, )).fetchone()
            except:
                message = ""


            if not message:
                # We try all the tables....
                for table in tables:
                    QUERY_EVENT_MESS = "SELECT message_string FROM {} WHERE message_identifier like ?".format(table)
                    message = provider_db.execute(QUERY_EVENT_MESS, (str_eventid, )).fetchone()
                    if message:
                        return message[0].strip()
                return ''

            return message[0].strip()
        except Exception as e:
            print(e)
            return ''


# def get_message_string(database, provider, eventid, lcid, vers):
#     try:
#         filename = database.split('/')[-1]
#         basename = './'
#         if len(database.split('/')[-1]) > 1:
#             basename = '/'.join(database.split('/')[:-1])
#             basename += '/'

#         conn = sqlite3.connect(database)

#         QUERY_PROVIDER_DB = """
#         SELECT database_filename FROM event_log_providers 
#             INNER JOIN message_file_per_event_log_provider ON 
#                 message_file_per_event_log_provider.event_log_provider_key = event_log_providers.event_log_provider_key
#             INNER JOIN message_files ON 
#                 message_files.message_file_key = message_file_per_event_log_provider.message_file_key 
#         WHERE log_source=?
#         """
#         database_filename = conn.execute(QUERY_PROVIDER_DB, (provider,)).fetchone()
#         logging.info('database for this provider is: {}'.format(database_filename))
#         #conn.close()
#         if not database_filename:
#             return ""
#         else:
#             database_filename = database_filename[0]
#         database_filename = basename + database_filename

#         conn = sqlite3.connect(database_filename)

#         cursor = conn.cursor()
#         cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
#         # conn = sqlite3.connect(database_filename)

#         tables = [table[0] for table in cursor.fetchall() if 'message_table_0x' in table[0]]

#         try:
#             table_name = 'message_table_0x{:08x}{}'.format(lcid, vers)
#             str_eventid = '%{:05x}'.format(eventid)
#             QUERY_EVENT_MESS = "SELECT message_string FROM {} WHERE message_identifier like ?".format(table_name)
#             message = conn.execute(QUERY_EVENT_MESS, (str_eventid, )).fetchone()
#         except:
#             message = ""

#         if not message:
#             # We try all the tables....
#             # conn.close()
#             for table in tables:
#                 QUERY_EVENT_MESS = "SELECT message_string FROM {} WHERE message_identifier like ?".format(table)
#                 # conn = sqlite3.connect(database_filename)
#                 message = conn.execute(QUERY_EVENT_MESS, (str_eventid, )).fetchone()
#                 if message:
#                     conn.close()
#                     return message[0].strip()
#                 # conn.close()

#             return ""

#         conn.close()    
#         return message[0].strip()
#     except Exception as e:
#         print(e)
#         return ""

def run():
    # Handle arguments
    argparser = argparse.ArgumentParser()
    argparser.add_argument("-v", "--verbosity", help="increase output verbosity", choices = LOG_VERBOSITY, default='INFO')

    argparser.add_argument('-d', '--database', required=True, help='Main winevt-kb database')
    argparser.add_argument('-p', '--provider', required=True, help='Event provider')
    argparser.add_argument('--eventid', required=True, type=int, help='Event id')
    argparser.add_argument('--lcid', required=False, type=int, default=0x409, help='Event id')
    argparser.add_argument('--vers', required=False, type=str, default='_6_1_7601_24168', help='vers / tag winver in winevt-kb database')
    
    

    args = argparser.parse_args()

    # configure logging
    logging.basicConfig(format=LOG_FORMAT, level=LOG_VERBOSITY[args.verbosity], datefmt='%Y-%m-%d %I:%M:%S')
    resolver = Resolver(args.database)
    logging.info(resolver.get_message_string(args.provider, args.eventid, args.lcid, args.vers))

    

if __name__ == '__main__':
    run()
    