# -*- coding: utf-8 -*-

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from collections import OrderedDict

FIELD_EVENTID = 'Event.System.EventID.text.keyword'
FIELD_CHANNEL = 'Event.System.Channel.keyword'

class Alert(object):

	def __init__(self, message = '', data =  OrderedDict()):
		self.message = message
		self.data = data

	def __getitem__(self, idx):
		return self.data[idx]

class Scenar(object):
	"""docstring for Scenar"""
	def __init__(self):
		super(Scenar).__init__()
		self.alerts = []
		
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
