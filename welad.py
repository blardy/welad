#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from scenario.logon import StatLogon, LogonHistory, RDPHistory
from scenario.services import StatServices, SearchKeyword, BITSService



"""
	Statistiques:
		- nb events
		- nb machines
		- Timeframe / eventlog

	Anomalies:
		- trigger sur 1 event
		- trigger sur 1 event + compute manuel (delta temps)
		- Agregation + threshold
		- Agregation + export (eg. BITS)


	Export CSV/TXT

"""

# class ClearLog(ElasticScenar):
# 	def __init__(self, host, index):
# 		super(ClearLog, self).__init__(host, index)

# 	def process(self):
# 		q1 = MultiMatch(query='1102', fields=['event.System.EventID.content'])
# 		q2 = MultiMatch(query='Security', fields=['event.System.Channel.keyword'])
# 		self.search = self.search.query(q1 & q2)
# 		self.resp = self.search.execute()

# 		print('Total hits: {}'.format(self.resp.hits.total))
# 		for hit in self.search.scan():
# 			print('[{}][{}] {}'.format(hit.event.System.Computer, hit.event.System.Channel, hit.event.UserData))		
# 			# todo: yield des alertes ?



def main():
	SCENARS = [StatLogon(), LogonHistory(), RDPHistory(), StatServices(), SearchKeyword(), BITSService()]
	SCENARS_DICT = {}
	for scenar in SCENARS:
		SCENARS_DICT[scenar.__class__.__name__] = scenar

	parser = argparse.ArgumentParser()
	subparsers = parser.add_subparsers(help='Scenarios',  dest='scenar')
	for scenar in SCENARS:
		p = subparsers.add_parser(scenar.__class__.__name__, help=scenar.help)
		scenar.add_argument(p)

	args = parser.parse_args()

	if SCENARS_DICT.get(args.scenar, False):
		SCENARS_DICT[args.scenar].init(args)
		SCENARS_DICT[args.scenar].process()

		# print alert if any

if __name__ == '__main__':
	main()