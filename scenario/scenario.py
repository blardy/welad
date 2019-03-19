# -*- coding: utf-8 -*-
import logging
import yaml

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from collections import OrderedDict
from scenario.utils import _get_max_len_by_line

from elasticsearch_dsl.query import MultiMatch, Range

FIELD_EVENTID = 'Event.System.EventID.text.keyword'
FIELD_CHANNEL = 'Event.System.Channel.keyword'

class Alerts(object):
	def __init__(self, header = [], data = [], please_do_not_sort_me=False):
		self.header = header
		self.data = data
		self.please_do_not_sort_me = please_do_not_sort_me


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
		parser.add_argument('--es_host', help="IP:port of elasticsearch master")
		parser.add_argument('--es_index', help="elasticsearch index to query")
		parser.add_argument('--es_user', default='', help="")
		parser.add_argument('--es_password', default='', help="")

		parser.add_argument('--system', required=False, help='Filter on system name (ie: plop-desktop)')
		parser.add_argument('--from', dest='_from', required=False, help='YYYY-MM-DDTHH:MM:SS')
		parser.add_argument('--to', dest='_to',required=False, help='YYYY-MM-DDTHH:MM:SS')
		parser.add_argument('--filter', required=False, help='Custom filter "Event.EventData.Data.SubjectUserName.keyword:plop"', action='append')

	def get_conf(self, key, default=None):
		return self.conf.get(self.__class__.__name__, {}).get(key, default)

	def _get_conf(self, classname, key, default=None):
		return self.conf.get(classname, {}).get(key, default)

	def set_conf(self, key, value):
		scenar_conf = self.conf.get(self.__class__.__name__, {})
		scenar_conf[key] = value
		self.conf[self.__class__.__name__] = scenar_conf

	def _set_conf(self, classname, key, value):
		scenar_conf = self.conf.get(classname, {})
		scenar_conf[key] = value
		self.conf[classname] = scenar_conf

	def init(self, args):
		self.args = args

		self.conf = {}
		if args.conf:
			self.conf = yaml.load(args.conf)
		logging.info(self.conf)
		if args.es_host:
			self._set_conf('ElasticScenario', 'es_host', args.es_host)
		if args.es_index:
			self._set_conf('ElasticScenario','es_index', args.es_index)
		if args.es_user:
			self._set_conf('ElasticScenario','es_user', args.es_user)
		if args.es_password:
			self._set_conf('ElasticScenario','es_password', args.es_password)
		logging.info(self.conf)


		self.index = self._get_conf('ElasticScenario', 'es_index', 'winevt-lab')
		self.bucket_size = self._get_conf('ElasticScenario', 'es_bucket_size', 6000)

		self.client = Elasticsearch([self._get_conf('ElasticScenario', 'es_host', '127.0.0.1')], http_auth=(self._get_conf('ElasticScenario', 'es_user', ''), self._get_conf('ElasticScenario', 'es_password', '')), timeout=self._get_conf('ElasticScenario', 'es_timeout', 30))
		self.search = Search(using=self.client, index=self.index)

		self.filter = None
		filters = []

		self.evt_time_field = self._get_conf('ElasticScenario', 'evt_time_field', 'Event.System.TimeCreated.SystemTime')
		if args._from and args._to:
			filters.append(Range(** {self.evt_time_field: {'gte': args._from, 'lte':  args._to}}))
		elif args._from:
			filters.append(Range(** {self.evt_time_field: {'gte': args._from}}))
		elif args._to:
			filters.append(Range(** {self.evt_time_field: {'lte': args._to}}))

		if args.system:
			filters.append(MultiMatch(query=args.system, fields=[self._get_conf('ElasticScenario', 'evt_system_field', 'Event.System.Computer')]))
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
