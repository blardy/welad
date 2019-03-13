# -*- coding: utf-8 -*-

from elasticsearch_dsl.query import MultiMatch
from elasticsearch_dsl import A
from scenario.scenario import *

import logging

class CSVExport(ElasticScenario):
	help = 'Export events matching the given keyword'

	def __init__(self):
		super(CSVExport, self).__init__()

	def add_argument(self, parser):
		super(CSVExport, self).add_argument(parser)
		parser.add_argument('--filter', help='Filter on field/value (ie: batch_id.keyword:mybatch or Event.System.Computer.keyword:PLOP-DESKTOP)')
		parser.add_argument('--keyword', required=True, help='keyword to search for')
		parser.add_argument('--separator', required=False, default='|', help='Field separator to use')

	def process(self):
		keyword_search = MultiMatch(query=self.args.keyword)
		if self.args.filter:
			data = self.args.filter.split(':')
			if len(data) != 2:
				logging.warning('Provided filter is not handle : {}'.format(data))
			else:
				keyword_search = keyword_search & MultiMatch(query=data[1], fields=[data[0]])

		self.search =self.search.query(keyword_search)
		self.resp = self.search.execute()
		logging.info(' => query: {}'.format(keyword_search))
		logging.info(' => Total hits: : {}'.format(self.resp.hits.total))

		print('Date / Time (UTC)|Computer Name|Matching Keyword|Channel|EventID|Description (short)|SID|Event Data')
		for hit in self.search.scan():
			computer = hit.Event.System.Computer
			timestamp = hit.Event.System.TimeCreated.SystemTime
			eventid = hit.Event.System.EventID.text
			desc = hit.Event.Description.short.strip()
			channel = hit.Event.System.Channel.strip()
			sid = hit.Event.System.Security.UserID.strip()

			if hit.Event.__dict__['_d_'].get('UserData', False):
				event_data = hit.Event.UserData
				event_data = event_data.__dict__['_d_']
				if event_data.get('EventData', False):
					event_data = event_data['EventData']
			elif hit.Event.__dict__['_d_'].get('EventData', False):
				event_data = hit.Event.EventData
				event_data = event_data.__dict__['_d_']
				if event_data.get('Data', False):
					event_data = event_data['Data']
			else:
				# logging.error('NOT HANDLE')
				# logging.error(json.dumps(hit.Event.__dict__['_d_'], indent=2))
				event_data = {'Error': 'Not HANDLE'}
				

			str_param = '; '.join( ['{}={}'.format(k,v) for k,v in event_data.items()] )
			str_param = str_param.replace('\n', '')

			print('{}|{}|{}|{}|{}|{}|{}|{}'.format(timestamp, computer,self.args.keyword, channel, eventid, desc, sid, str_param))