# -*- coding: utf-8 -*-

from elasticsearch_dsl.query import MultiMatch
from scenario.scenario import ElasticScenario

"""
	All scenarios related about logon / logoff activities
"""

class LogonHistory(ElasticScenario):
	help = 'Extract logon history'

	def process(self):
		# 4624 + 4625
		logon = (MultiMatch(query='4624', fields=['event.System.EventID.content']) | MultiMatch(query='4625', fields=['event.System.EventID.content'])) & MultiMatch(query='Security', fields=['event.System.Channel.keyword'])
		# RDP

		self.search = self.search.query(logon)
		self.resp = self.search.execute()

		print('Having {} of events:'.format(self.resp.hits.total))
		for hit in self.search.scan():
			print(hit.event.System.EventID.content)
		

class StatLogon(ElasticScenario):
	help = 'Extract stats about logon'

	def __init__(self):
		super(StatLogon, self).__init__()

	def process(self):
		q1 = MultiMatch(query='4624', fields=['event.System.EventID.content'])
		q2 = MultiMatch(query='Security', fields=['event.System.Channel.keyword'])
		self.search = self.search.query(q1 & q2)
		self.resp = self.search.execute()

		print('Total hits: {}'.format(self.resp.hits.total))
		test = {}

		process = set()

		for hit in self.search.scan():
			# print(hasattr(hit.event.EventData, 'ProcessName'))
			# print('ProcessName' in hit.event.EventData)
			if 'ProcessName' in hit.event.EventData and hit.event.EventData.ProcessName != '-':
				process.add(hit.event.EventData.ProcessName)

				# print('[{}][{}] {}'.format(hit.event.System.Computer, hit.event.System.Channel, hit.event.EventData.ProcessName))		


			# todo: yield des alertes ?

		print(process)