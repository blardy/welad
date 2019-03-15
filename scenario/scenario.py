# -*- coding: utf-8 -*-
import logging

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from collections import OrderedDict

FIELD_EVENTID = 'Event.System.EventID.text.keyword'
FIELD_CHANNEL = 'Event.System.Channel.keyword'

class Alerts(object):
	def __init__(self, header = [], data = []):
		self.header = header
		self.data = data


	def init(self, header):
		if not header:
			logging.critical('Header is empty... abort')
			return False

		self.header = header
		self.sizes = [len(x) for x in header]
		return True

	def add_alert(self, alert):
		if not self.header:
			logging.critical('Header is empty... abort')
			return False

		if len(alert) != len(self.header):
			logging.critical('Header len [{}] is different from alert len [{}]....abort'.format(len(self.header), len(alert)))
			return False

		self.data.append(alert)

		# the idea is to get the max size for each fields
		self.sizes = [ max(len(str(x)), self.sizes[idx]) for idx, x in enumerate(alert)]


class Scenar(object):
	"""docstring for Scenar"""
	def __init__(self):
		super(Scenar).__init__()
		self.alert = Alerts()
		
	def add_argument(self, parser):
		pass

	def init(self, args):
		pass

	def process(self):
		pass


class ElasticScenario(Scenar):
	help = 'Abstract class for scenario using elasticsearch'

	def __init__(self):
		super(ElasticScenario, self).__init__()
	
	def add_argument(self, parser):
		parser.add_argument('--elastic', required=True, help="IP:port of elasticsearch master")
		parser.add_argument('--index', required=True, help="elasticsearch index to query")
		parser.add_argument('--es_user', default='', help="")
		parser.add_argument('--es_password', default='', help="")


	def init(self, args):
		self.args = args
		self.elastic = args.elastic
		self.index = args.index

		self.client = Elasticsearch([self.elastic], http_auth=(args.es_user, args.es_password), timeout=30)
		self.search = Search(using=self.client, index=self.index)

	def process(self):
		pass
