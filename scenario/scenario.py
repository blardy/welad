# -*- coding: utf-8 -*-
import logging

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from collections import OrderedDict
from scenario.utils import _get_max_len_by_line

from elasticsearch_dsl.query import MultiMatch, Range

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
		self.sizes = [ max(_get_max_len_by_line(str(x)), self.sizes[idx]) for idx, x in enumerate(alert)]


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

		parser.add_argument('--system', required=False, help='Filter on system name (ie: plop-desktop)')
		parser.add_argument('--from', dest='_from', required=False, help='YYYY-MM-DDTHH:MM:SS')
		parser.add_argument('--to', dest='_to',required=False, help='YYYY-MM-DDTHH:MM:SS')
		parser.add_argument('--filter', required=False, help='Custom filter "Event.EventData.Data.SubjectUserName.keyword:plop"', action='append')


	def init(self, args):
		self.args = args
		self.elastic = args.elastic
		self.index = args.index
		self.bucket_size = 9000

		self.client = Elasticsearch([self.elastic], http_auth=(args.es_user, args.es_password), timeout=30)
		self.search = Search(using=self.client, index=self.index)

		self.filter = None
		filters = []
		if args._from and args._to:
			filters.append(Range(** {'Event.System.TimeCreated.SystemTime': {'gte': args._from, 'lte':  args._to}}))
		elif args._from:
			filters.append(Range(** {'Event.System.TimeCreated.SystemTime': {'gte': args._from}}))
		elif args._to:
			filters.append(Range(** {'Event.System.TimeCreated.SystemTime': {'lte': args._to}}))

		if args.system:
			filters.append(MultiMatch(query=args.system, fields=['Event.System.Computer']))
		if args.filter:
			for f in args.filter:
				data = f.split(':')
				field = data[0]
				value = ':'.join(data[1:]) # in case there is ':' char in the value...
				filters.append(MultiMatch(query=value, fields=[field]))

		if filters:
			self.filter = filters[0]
			for f in filters[1:]:
				self.filter &= f

		logging.info(self.filter)

	def process(self):
		pass
