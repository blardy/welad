# -*- coding: utf-8 -*-

from elasticsearch_dsl.query import MultiMatch
from elasticsearch_dsl import A
from scenario.scenario import *

import logging

class Search(ElasticScenario):
	help = 'Export events matching the given keyword'

	def __init__(self):
		super(Search, self).__init__()

	def add_argument(self, parser):
		super(Search, self).add_argument(parser)
		parser.add_argument('--keyword', required=True, help='keyword to search for')

	def process(self):
		keyword_search = MultiMatch(query=self.args.keyword)
		if self.filter:
			keyword_search &= self.filter

		self.search =self.search.query(keyword_search)
		self.resp = self.search.execute()
		logging.info(' => query: {}'.format(keyword_search))
		logging.info(' => Total hits: : {}'.format(self.resp.hits.total))

		self.alert.init(['Date / Time (UTC)', 'Computer Name', 'Matching Keyword', 'Channel', 'EventID', 'Description (short)', 'Event Data'])
		for hit in self.search.scan():
			d_hit = hit.to_dict()
			# Generic fields
			computer = self.get_value(d_hit, self.get_mapping('evt_system_field'))
			timestamp = self.get_value(d_hit, self.get_mapping('evt_time_field'))
			event_id = self.get_value(d_hit, self.get_mapping('evt_event_id_field'))
			desc = self.get_value(d_hit, self.get_mapping('evt_desc_field'))
			case = self.get_value(d_hit, self.get_mapping('case_field'))
			channel = self.get_value(d_hit, self.get_mapping('evt_channel_field'))

			data = self.get_value(d_hit, self.get_mapping('evt_event_data_1_field'), None)
			if not data:
				data = self.get_value(d_hit, self.get_mapping('evt_event_data_2_field'), None)
	
			str_param = ''
			if data:
				str_param = '; '.join( ['{}={}'.format(k,v) for k,v in data.items()] )
				str_param = str_param.replace('\n', '')

			self.alert.add_alert([timestamp, computer,self.args.keyword, channel, event_id, desc, str_param])