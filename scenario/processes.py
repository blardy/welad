# -*- coding: utf-8 -*-

from elasticsearch_dsl.query import MultiMatch, Range
from elasticsearch_dsl import A
from scenario.scenario import *
from scenario.utils import _get_date

import logging
import json


"""
	OPTIM:
		+ ProcessTree
			- Change how the process tree is build as it is slow... and it is doing much queries for building childs....

	SCENARIO:
		+ ProcessAnomaly
			- from process tree ? => powershell=>csc=>cvtres // svchost=>cmd/powershell
"""
class SuspiciousProcess(ElasticScenario):
	help = 'Extract Suspicious processes'

	def __init__(self):
		super(SuspiciousProcess, self).__init__()

	def add_argument(self, parser):
		super(SuspiciousProcess, self).add_argument(parser)

	def process(self):
		processes_search =  MultiMatch(query=4688, fields=[self.get_mapping('evt_event_id_field')])

		if self.filter:
			processes_search &= self.filter

		self.alert.init(['Date / Time (UTC)', 'System', 'UserName', 'Session ID', 'Image Path', 'Parent'])

		try:
			field_path = self.get_conf('evt_image_path', 'Event.EventData.Data.NewProcessName')
			keywords = self.get_conf('blacklist', default=[])
			q_keyword = MultiMatch(query=keywords[0], fields=[field_path])
			for keyword in keywords[1:]:
				q_keyword |= MultiMatch(query=keyword, fields=[field_path])

			processes_search = processes_search & q_keyword
			logging.info(' => query: {}'.format(processes_search))
			self.search =self.search.query(processes_search)
			self.resp = self.search.execute()
			logging.info(' => Total hits: : {}'.format(self.resp.hits.total))

			for hit in self.search.scan():
				computer = hit.winlog.computer_name
				d_hit = hit.to_dict()
				timestamp = d_hit.get('@timestamp')
				eventid = hit.winlog.event_id
				desc = hit.description.short.strip()
				channel = hit.winlog.channel.strip()
				# Specific
				process = hit.winlog.event_data.NewProcessName
				pid = hit.winlog.event_data.NewProcessId
				ppid = hit.winlog.event_data.ProcessId
				logon_id = hit.winlog.event_data.SubjectLogonId
				logon_domain = hit.winlog.event_data.SubjectDomainName
				logon_account = hit.winlog.event_data.SubjectUserName
				logon_sid = hit.winlog.event_data.SubjectUserSid
				try:
					parent_name = '{} ({})'.fromat(hit.winlog.event_data.ParentProcessName, int(ppid, 16))
				except:	
					parent_name = int(ppid, 16)

				self.alert.add_alert([timestamp, computer, logon_account, logon_id, process, parent_name])
		except Exception as e:
			logging.error(e)

class Process(object):
	"""Process object 4688 + 4689 docs"""
	def __init__(self, system, image_path, pid, ppid, begin, end, logon_id, logon_domain, logon_account, logon_sid, parent_name = None):
		super(Process, self).__init__()
		self.system = system
		self.pid = pid
		self.ppid = ppid
		self.begin = begin
		self.end = end
		self.logon_id = logon_id
		self.logon_domain = logon_domain
		self.logon_account = logon_account
		self.logon_sid = logon_sid
		self.image_path = image_path
		self.parent_name = parent_name

		self.childs = None

	def uid(self):
		return '{}-pid:{}-ppid:{}-begin:{}'.format(self.system, self.pid, self.ppid, self.begin)

	def __str__(self):
		return self.image_path + ' (pid: {}; ppid:{})'.format(int(self.pid, 16), int(self.ppid, 16))

	def visit_childs(self, indent = 2, root = False):
		s = ' ' * indent + '\\=> '
		s += self.image_path + ' (pid: {}; ppid:{})'.format(int(self.pid, 16), int(self.ppid, 16))

		if not root:
			yield self, s

		if self.childs:
			child = [child_process for child_uid, child_process in self.childs.items()]

			for child_process in sorted(child, key=lambda process: process.begin):
				yield from child_process.visit_childs(indent + 2)

	def pretty_print(self, indent = 4, details = False):
		s = ' ' * indent 
		if details and self.parent_name and self.parent_name != 'None':
			s += '[{}]\n'.format(self.parent_name)
			indent += 2
			s += ' ' * indent 

		# s += '\\=> ' if not details else '- [{}][{}] '.format(self.system.split('.')[0], self.begin)
		s += '\\=> ' #if not details else '- [{}][{}] '.format(self.system.split('.')[0], self.begin)
		s += self.image_path + ' (pid: {}; ppid:{})'.format(int(self.pid, 16), int(self.ppid, 16))

		s += '\n'

		if self.childs:
			child = [child_process for child_uid, child_process in self.childs.items()]

			for child_process in sorted(child, key=lambda process: process.begin):
				s += child_process.pretty_print(indent + 4)

		return s

	def find_exit(self, exit_points):
		try:
			#  { computer : { logon_id : { process: { pid : [timestamp1,...., N ] }}}}
			timestamps = exit_points[self.system][self.logon_id][self.image_path][self.pid]
			if len(timestamps) == 1:
				self.end = timestamps[0]
			elif len(timestamps) == 0:
				logging.debug('No suitable end for process found...')
				pass
			else:
				# need to take the most suitable exit points (ie: the most near the current process)
				logging.info('Found {} exit points: {}'.format(len(timestamps), timestamps))
				most_suitable = None

				begin_date = _get_date(self.begin)

				for exit_idx, exit_timestamp in enumerate(timestamps):
					exit_date = _get_date(exit_timestamp)
					if exit_date < begin_date:
						continue

					delta = exit_date - begin_date
					if not most_suitable or delta < most_suitable[0] :
						most_suitable = (delta, exit_timestamp)

				if most_suitable:
					self.end = most_suitable[1]
					logging.info('Most suitable exit point is : {}'.format(most_suitable[1]))
				else:
					logging.info('No suitable exit point found :')
		except:
			return False
		return True

	def get_childs(self, search_object, scenar):
		""" It returns a dict containing childs processes. Keys are UID of childs
		It is SLOW as it query the ES for findings childs.
		"""
		if self.childs is not None:
			return self.childs

		self.childs = {}

		# A child is define by having the pid (NewProcessId) of the current process as PPID (ProcessId)
		#  AND coming from same system (Computer)
		#  AND coming from same logon Session (SubjectLogonId)
		#  AND that was spawned when current process was alive (begin < child < end)
		evt_time_field = scenar.get_mapping('evt_time_field')
		time_filter = Range(** {evt_time_field: {'gte': self.begin}})
		if self.end:
			time_filter = Range(** {evt_time_field: {'gte': self.begin, 'lte': self.end}})

		child_query = MultiMatch(query=4688, fields=[scenar.get_mapping('evt_event_id_field')]) \
			& MultiMatch(query=self.system, fields=[scenar.get_mapping('evt_system_field_k')]) \
			& MultiMatch(query=self.pid, fields=[scenar.get_mapping('evt_pid_k')]) \
			& time_filter

		search_object = search_object.query(child_query)
		response = search_object.execute()
		for hit in search_object.scan():
			d_hit = hit.to_dict()
			# Generic fields
			computer = scenar.get_value(d_hit, scenar.get_mapping('evt_system_field'))
			timestamp = scenar.get_value(d_hit, scenar.get_mapping('evt_time_field'))
			event_id = scenar.get_value(d_hit, scenar.get_mapping('evt_event_id_field'))
			desc = scenar.get_value(d_hit, scenar.get_mapping('evt_desc_field'))
			case = scenar.get_value(d_hit, scenar.get_mapping('case_field'))

			channel = scenar.get_value(d_hit, scenar.get_mapping('evt_channel_field'))
			# Generic

			sid = '-'
			process = scenar.get_value(d_hit, scenar.get_mapping('evt_image_path_field'))
			pid = scenar.get_value(d_hit, scenar.get_mapping('evt_pid_field'))

			# Specific
			process = scenar.get_value(d_hit, scenar.get_mapping('evt_process_name_field'))
			pid = scenar.get_value(d_hit, scenar.get_mapping('evt_4688_pid_field'))
			ppid = scenar.get_value(d_hit, scenar.get_mapping('evt_ppid_field'))
			logon_id = scenar.get_value(d_hit, scenar.get_mapping('evt_logon_id_field'))
			logon_domain = scenar.get_value(d_hit, scenar.get_mapping('evt_logon_domain_field'))
			logon_account = scenar.get_value(d_hit, scenar.get_mapping('evt_logon_account_field'))
			logon_sid = scenar.get_value(d_hit, scenar.get_mapping('evt_sid_field'))

			# Todo : get end of process ? for handling depth
			child = Process(computer, process, pid, ppid, timestamp, None, logon_id, logon_domain, logon_account, logon_sid)
			self.childs[child.uid()] = child
			
		return self.childs

class ProcessStat(ElasticScenario):
	help = 'Prints stats about processes'
	"""Prints stats about processes
	 ______________________________________________________________________________________________________________________________________________________________________________________
	|            System            |                 UserName                 |          Session ID          |  Nb Process   |        First Process         |         Last Process         |
	 ______________________________________________________________________________________________________________________________________________________________________________________
	|          PLOP-DESK           |               PLOP-DESK$                |      0x00000000000003e7      |    701368     |   2019-01-20T06:56:25.015Z   |   2019-03-08T12:02:27.045Z   |
	|          PLOP-DESK           |               PLOP-DESK$                |      0x00000000000003e4      |      136      |   2019-01-21T03:08:35.984Z   |   2019-03-08T11:45:49.557Z   |
	|          PLOP-DESK           |               admin.plop                |      0x000000001458b9c7      |     1779      |   2019-02-10T20:13:54.705Z   |   2019-02-11T01:11:39.068Z   |
	|          PLOP-DESK           |               admin.pilou               |      0x00000000118aaec6      |      887      |   2019-02-10T16:30:26.592Z   |   2019-02-10T20:22:35.461Z   |

	Can use filters:
	  --process_name: Filter on teh image path of the process (ie: "temp" will match all processes that are having "temp" in the path, "cmd.exe" will match all processes that are having "cmd.exe" in the path)
	  --_from and --_to : Those filters MUST be used together and specify the timeframe
	  --system: Filter on system name (ie: PLOP-DESK)
	  --username: Filter on user name (ie: admin.plop)
	"""
	def __init__(self):
		super(ProcessStat, self).__init__()

	def add_argument(self, parser):
		super(ProcessStat, self).add_argument(parser)
		parser.add_argument('--process_name', required=False, help='Filter on field Event.EventData.Data.NewProcessName (ie: powershell.exe)')
		parser.add_argument('--logon_id', required=False, help='Filter on logon Session ID (ie: 0x000000004e9f7608)')
		parser.add_argument('--username', required=False, help='Filter on logon username (ie: plop)')

	def process(self):
		processes_search =  MultiMatch(query=4688, fields=[self.get_mapping('evt_event_id_field')])
		if self.args.username:
			processes_search = processes_search & MultiMatch(query=self.args.username, fields=[self.get_mapping('evt_username_field_k')])
		if self.args.logon_id:
			processes_search = processes_search & MultiMatch(query=self.args.logon_id, fields=[self.get_mapping('evt_logon_id_field_k')])
		if self.args.process_name:
			processes_search = processes_search & MultiMatch(query=self.args.process_name, fields=[self.get_mapping('evt_image_path_k')])

		if self.filter:
			processes_search &= self.filter

		logging.info(' => query: {}'.format(processes_search))
		self.search = self.search.query(processes_search)

		self.search.aggs.bucket('computer', 'terms', field=self.get_mapping('evt_system_field_k'))\
		.bucket('username', 'terms', field=self.get_mapping('evt_username_field_k'))\
		.bucket('logon_id', 'terms', field=self.get_mapping('evt_logon_id_field_k'))\
		.metric('first_process', 'min', field=self.get_mapping('evt_time_field'))\
		.metric('last_process', 'max', field=self.get_mapping('evt_time_field'))
		self.resp = self.search.execute()

		self.alert.init(['System', 'UserName', 'Session ID', 'Nb Process', 'First Process', 'Last Process'])
		logging.debug('=========plop=============')
		logging.debug(self.resp.aggregations.to_dict())
		logging.debug(self.resp.to_dict())
		for computer_data in self.resp.aggregations.computer:
			logging.debug(computer_data)
			for username_data in computer_data.username:
				for logon_id_data in username_data.logon_id:
					self.alert.add_alert([computer_data.key.split('.')[0], username_data.key, logon_id_data.key, logon_id_data.doc_count, logon_id_data.first_process.value_as_string, logon_id_data.last_process.value_as_string])
		logging.debug('=========plop=============')

class ProcessTree(ElasticScenario):
	help = 'Rebuild process Tree'

	def __init__(self):
		super(ProcessTree, self).__init__()

	def add_argument(self, parser):
		super(ProcessTree, self).add_argument(parser)

		parser.add_argument('--process_name', required=False, help='Filter on field Event.EventData.Data.NewProcessName (ie: powershell.exe)')
		parser.add_argument('--logon_id', required=False, help='Filter on logon Session ID (ie: 0x000000004e9f7608)')
		parser.add_argument('--username', required=False, help='Filter on logon username (ie: plop)')
		parser.add_argument('--process_with_child_only', action='store_true', help='only prints processes that have childs')

	def find_all_possible_exit_points(self, process_list, max_query_size=100):
		exit_points = {}

		exit_query = MultiMatch(query=4689, fields=[self.get_mapping('evt_event_id_field')])
		sub_queries = []
		for current_process in process_list:
			sub_q = MultiMatch(query=current_process.pid, fields=[self.get_mapping('evt_pid_field_k')]) \
				& MultiMatch(query=current_process.system, fields=[self.get_mapping('evt_system_field_k')]) \
				& MultiMatch(query=current_process.logon_id, fields=[self.get_mapping('evt_logon_id_field_k')]) \
				& MultiMatch(query=current_process.image_path, fields=[self.get_mapping('evt_image_path_field_k')])


			sub_queries.append(sub_q)

		sub_queries = [sub_queries[i:i+max_query_size] for i in range(0, len(sub_queries), max_query_size)]
		for sub_query in sub_queries:
			all_sub_q = sub_query[0]
			for sub_q in sub_query[1:]:
				all_sub_q |= sub_q
			query = exit_query & all_sub_q

			exit_search = Search(using=self.client, index=self.index)
			exit_search = exit_search.query(query)
			exit_processes_resp = exit_search.execute()
			logging.info(' => Total hits: : {}'.format(exit_processes_resp.hits.total))
			for hit in exit_search.scan():
				d_hit = hit.to_dict()
				# Generic fields
				computer = self.get_value(d_hit, self.get_mapping('evt_system_field'))
				timestamp = self.get_value(d_hit, self.get_mapping('evt_time_field'))
				event_id = self.get_value(d_hit, self.get_mapping('evt_event_id_field'))
				desc = self.get_value(d_hit, self.get_mapping('evt_desc_field'))
				case = self.get_value(d_hit, self.get_mapping('case_field'))

				channel = self.get_value(d_hit, self.get_mapping('evt_channel_field'))
				# Generic

				sid = '-'
				process = self.get_value(d_hit, self.get_mapping('evt_image_path_field'))
				pid = self.get_value(d_hit, self.get_mapping('evt_pid_field'))
				
				logon_id = self.get_value(d_hit, self.get_mapping('evt_logon_id_field'))
				logon_domain = self.get_value(d_hit, self.get_mapping('evt_logon_domain_field'))
				logon_account = self.get_value(d_hit, self.get_mapping('evt_logon_account_field'))
				logon_sid = self.get_value(d_hit, self.get_mapping('evt_sid_field'))

				# Build dict
				#  { computer : { logon_id : { process: { pid : [timestamp1,...., N ] }}}}
				computer_exits = exit_points.get(computer, {})
				logon_id_exits = computer_exits.get(logon_id, {})
				process_exit = logon_id_exits.get(process, {})
				pids_exit = process_exit.get(pid, [])
				pids_exit.append(timestamp)
				process_exit[pid] = pids_exit
				logon_id_exits[process] = process_exit
				computer_exits[logon_id] = logon_id_exits
				exit_points[computer] = computer_exits

		logging.debug(json.dumps(exit_points, indent=2))

		return exit_points

	def process(self):
		processes_search =  MultiMatch(query='4688', fields=[self.get_mapping('evt_event_id_field')])

		if self.args.username:
			processes_search = processes_search & MultiMatch(query=self.args.username, fields=[self.get_mapping('evt_logon_account_field_k')])
		if self.args.logon_id:
			processes_search = processes_search & MultiMatch(query=self.args.logon_id, fields=[self.get_mapping('evt_logon_id_field_k')])
		if self.args.process_name:
			processes_search = processes_search & MultiMatch(query=self.args.process_name, fields=[self.get_mapping('evt_image_path_field_k')])

		if self.filter:
			processes_search &= self.filter

		logging.info(' => query: {}'.format(processes_search))
		self.search =self.search.query(processes_search)
		self.resp = self.search.execute()
		logging.info(' => Total hits: : {}'.format(self.resp.hits.total))

		PROCESS_ALL = []
		PROCESS_VALID = []

		PROCESS_TREE = {}
		PARENT_PROCESS_OF_CHILD = {}


		PROCESS_TOO_MANY_EXIT = {}
		PROCESS_NO_EXIT = {}

		#
		#  1 - Get all processes
		#
		for hit in self.search.scan():
			d_hit = hit.to_dict()
			# Generic fields
			computer = self.get_value(d_hit, self.get_mapping('evt_system_field'))
			timestamp = self.get_value(d_hit, self.get_mapping('evt_time_field'))
			event_id = self.get_value(d_hit, self.get_mapping('evt_event_id_field'))
			desc = self.get_value(d_hit, self.get_mapping('evt_desc_field'))
			case = self.get_value(d_hit, self.get_mapping('case_field'))

			channel = self.get_value(d_hit, self.get_mapping('evt_channel_field'))
			# Generic

			sid = '-'
			process = self.get_value(d_hit, self.get_mapping('evt_image_path_field'))
			pid = self.get_value(d_hit, self.get_mapping('evt_pid_field'))

			# Specific
			process = self.get_value(d_hit, self.get_mapping('evt_process_name_field'))
			pid = self.get_value(d_hit, self.get_mapping('evt_4688_pid_field'))
			ppid = self.get_value(d_hit, self.get_mapping('evt_ppid_field'))
			logon_id = self.get_value(d_hit, self.get_mapping('evt_logon_id_field'))
			logon_domain = self.get_value(d_hit, self.get_mapping('evt_logon_domain_field'))
			logon_account = self.get_value(d_hit, self.get_mapping('evt_logon_account_field'))
			logon_sid = self.get_value(d_hit, self.get_mapping('evt_sid_field'))
			parent_name = self.get_value(d_hit, self.get_mapping('evt_pname_field'), default=None)

			# Create process object (missing the end date...)
			current_process = Process(computer, process, pid, ppid, timestamp, None, logon_id, logon_domain, logon_account, logon_sid, parent_name=parent_name)
			PROCESS_ALL.append(current_process)

		#
		#  2 - For each process, search the exit point
		#

		exit_points = self.find_all_possible_exit_points(PROCESS_ALL)
		for current_process in PROCESS_ALL:
			current_process.find_exit(exit_points)

		#
		#  3 - Find childs
		#       get_childs is querying the ES... could by optimize by getting all processes into mem (1 query)...

		cpt = 0
		for current_process in PROCESS_ALL:
		# for current_process in PROCESS_VALID:
			cpt += 1
			logging.info('Computing childs: {}/{}'.format(cpt, len(PROCESS_ALL)))			
			for child_uid in current_process.get_childs(Search(using=self.client, index=self.index), self).keys():
				# look if we already handle this child process to build the tree
				if PROCESS_TREE.get(child_uid, False):
					# We already handle this child
					#   1 - Delete child process from root PROCESS_TREE AND Update current process
					current_process.childs[child_uid] = PROCESS_TREE.pop(child_uid)

				PARENT_PROCESS_OF_CHILD[child_uid] = current_process

			# Check if the current process has been seen as a child of an other process !!!
			if PARENT_PROCESS_OF_CHILD.get(current_process.uid(), False):
				parent = PARENT_PROCESS_OF_CHILD[current_process.uid()]
				parent.childs[current_process.uid()] = current_process
			else:
				PROCESS_TREE[current_process.uid()] = current_process

		#
		#  4 - Raise alerts // print... !!!
		#
		self.alert.init(['System', 'Process', 'Date / Time (UTC)', 'username', 'Tree'])
		self.alert.please_do_not_sort_me = True
		root_processes = [process for uid, process in PROCESS_TREE.items()]
		for process in sorted(root_processes, key=lambda process: process.begin):

			self.alert.add_alert([process.system.split('.')[0], process.image_path, process.begin, process.logon_account, str(process)])

			if not self.args.process_with_child_only or len(process.childs) > 0:
				# self.alert.add_alert([process.system.split('.')[0], process.image_path, process.begin, process.logon_account, process.pretty_print(details=True)])
				for child, mess in process.visit_childs(root=True):
					self.alert.add_alert([child.system.split('.')[0], '', child.begin, child.logon_account, mess])
					# print(mess)


