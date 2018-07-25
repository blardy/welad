# -*- coding: utf-8 -*-

from elasticsearch_dsl.query import MultiMatch
from scenario.scenario import *

from urllib.parse import urlparse

import json

class SearchKeyword(ElasticScenario):
	def __init__(self):
		super(SearchKeyword, self).__init__()

	def process(self):
		services = MultiMatch(query='bits')
		self.search = self.search.query(services)
		self.resp = self.search.execute()


		print('Total hits: {}'.format(self.resp.hits.total))
		for hit in self.search.scan():
			print(hit)



class BITSService(ElasticScenario):
	def __init__(self):
		super(BITSService, self).__init__()

	def add_argument(self, parser):
		super(BITSService, self).add_argument(parser)
		parser.add_argument('--verbose', action='store_true')


	def process(self):
		bits_service = (MultiMatch(query='60', fields=[FIELD_EVENTID]) | MultiMatch(query='61', fields=[FIELD_EVENTID]) ) & MultiMatch(query='Microsoft-Windows-Bits-Client/Operational', fields=[FIELD_CHANNEL])
		self.search = self.search.query(bits_service)
		self.resp = self.search.execute()

		stats = {}

		print('Total hits: {}'.format(self.resp.hits.total))
		for hit in self.search.scan():
			url = urlparse(hit.Event.EventData.Data.url)

			stats[url.netloc] = stats.get(url.netloc, 0) + 1
			if self.args.verbose:
				print(url)

		print(json.dumps(stats, indent=2))


"""
	Should be done using aggregation !
"""
class StatServices(ElasticScenario):
	help = 'Extract stats about services'

	def __init__(self):
		super(StatServices, self).__init__()

	def process(self):
		services = MultiMatch(query='7036', fields=[FIELD_EVENTID]) & MultiMatch(query='System', fields=[FIELD_CHANNEL])
		self.search = self.search.query(services)
		self.resp = self.search.execute()

		print('Total service hits: {}'.format(self.resp.hits.total))

		services_stats = {}

		for hit in self.search.scan():
			svc_name = hit.Event.EventData.Data.param1
			svc_state = hit.Event.EventData.Data.param2
			evt_date = hit['@timestamp']

			stat = services_stats.get(svc_name, {})
			stat['first_seen'] = min(stat.get('first_seen', evt_date), evt_date)
			stat['last_seen'] = max(stat.get('last_seen', evt_date), evt_date)

			if svc_state == 'running':
				stat['nb_start'] = stat.get('nb_start', 0) + 1

			services_stats[svc_name] = stat


		header = ['Service Name', 'First Seen', 'Last Seen', 'nb_start']
		SEPARATOR = '|'
		print(SEPARATOR.join(header))
		for service, stat in services_stats.items():
			print(SEPARATOR.join([service, stat['first_seen'], stat['last_seen'], str(stat.get('nb_start', 0))]))

