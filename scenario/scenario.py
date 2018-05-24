# -*- coding: utf-8 -*-

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search


class Scenar(object):
	"""docstring for Scenar"""
	def __init__(self):
		super(Scenar).__init__()
		
	def add_argument(self, parser):
		pass

	def init(self, args):
		pass

	def process(self):
		pass


class ElasticScenario(object):
	help = 'Abstract class for scenario using elasticsearch'

	def __init__(self):
		super(ElasticScenario, self).__init__()
	
	def add_argument(self, parser):
		parser.add_argument('--elastic', required=True, help="IP:port of elasticsearch master")
		parser.add_argument('--index', required=True, help="elasticsearch index to query")


	def init(self, args):
		self.elastic = args.elastic
		self.index = args.index

		self.client = Elasticsearch([self.elastic])
		self.search = Search(using=self.client, index=self.index)

	def process(self):
		pass