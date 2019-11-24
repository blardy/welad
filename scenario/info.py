# -*- coding: utf-8 -*-

from elasticsearch_dsl.query import MultiMatch, Range
from elasticsearch_dsl import A
from scenario.scenario import *
from scenario.utils import *

import json
import re
import base64
import gzip
import binascii
import datetime

"""
	Extract Log timeframe for each systems
"""
class LogInfo(ElasticScenario):
	def __init__(self):
		super(LogInfo, self).__init__()

	def add_argument(self, parser):
		super(LogInfo, self).add_argument(parser)
		parser.add_argument('--fmt', required=False, default='%Y-%m-%dT%H:%M:%S.%fZ', help='Change format of time')


	def process(self):
		if self.filter:
			self.search = self.search.query(self.filter)

		self.search.aggs.bucket('case', 'terms', field=self.get_mapping('case_field'), size = self.bucket_size)\
			.bucket('computer', 'terms', field=self.get_mapping('evt_system_field_k'), size = self.bucket_size)\
			.metric('first_event', 'min', field=self.get_mapping('evt_time_field'))\
			.metric('last_event', 'max', field=self.get_mapping('evt_time_field'))

		self.alert.init(['Case', 'Computer Name', 'First Event', 'Last Event', 'Total Event'])
		self.resp = self.search.execute()
		for case_data in self.resp.aggregations.case:
			for computer_data in case_data.computer:
				first = datetime.datetime.strptime(computer_data.first_event.value_as_string, '%Y-%m-%dT%H:%M:%S.%fZ')
				last = datetime.datetime.strptime(computer_data.last_event.value_as_string, '%Y-%m-%dT%H:%M:%S.%fZ')

				self.alert.add_alert([case_data.key, computer_data.key, first.strftime(self.args.fmt), last.strftime(self.args.fmt), computer_data.doc_count])

"""
	Extract case information
"""
class CaseInfo(ElasticScenario):
	def __init__(self):
		super(CaseInfo, self).__init__()

	def process(self):
		if self.filter:
			self.search = self.search.query(self.filter)

		self.search.aggs.bucket('case', 'terms', field=self.get_mapping('case_field'), size = self.bucket_size)

		self.alert.init(['Case', 'Total Event'])
		self.resp = self.search.execute()
		for case_data in self.resp.aggregations.case:
			self.alert.add_alert([case_data.key, case_data.doc_count])

