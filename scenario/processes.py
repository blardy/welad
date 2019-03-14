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
			- Todo :) from temp, appdata...;
			- from process tree ? => powershell=>csc=>cvtres // svchost=>cmd/powershell
			- from whitelist/blacklist
"""

class Process(object):
	"""Process object 4688 + 4689 docs"""
	def __init__(self, system, image_path, pid, ppid, begin, end, logon_id, logon_domain, logon_account, logon_sid):
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

		self.childs = None

	def uid(self):
		return '{}-pid:{}-ppid:{}-begin:{}'.format(self.system, self.pid, self.ppid, self.begin)

	def __str__(self):
		return 'Process "{}" spawned by {}\\{} ({})'.format(self.image_path, self.logon_domain, self.logon_account, self.logon_sid)

	def pretty_print(self, indent = 4, details = False):
		s = ' ' * indent 
		s += '|=> ' if not details else '- [{}][{}] '.format(self.system.split('.')[0], self.begin)
		s += self.image_path + ' (pid: {}; ppid:{})'.format(int(self.pid, 16), int(self.ppid, 16))
		if details:
			s += '  [created by {}\\{} ({}) Logon ID: {}]'.format(self.logon_domain, self.logon_account, self.logon_sid, self.logon_id)

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

	def get_childs(self, search_object):
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
		time_filter = Range(** {'@timestamp': {'gte': self.begin}})
		if self.end:
			time_filter = Range(** {'@timestamp': {'gte': self.begin, 'lte': self.end}})

		child_query = MultiMatch(query='4688', fields=[FIELD_EVENTID]) \
			& MultiMatch(query=self.system, fields=['Event.System.Computer.keyword']) \
			& MultiMatch(query=self.pid, fields=['Event.EventData.Data.ProcessId.keyword']) \
			& time_filter

		search_object = search_object.query(child_query)
		response = search_object.execute()
		for hit in search_object.scan():
			# Generic
			computer = hit.Event.System.Computer
			timestamp = hit.Event.System.TimeCreated.SystemTime
			eventid = hit.Event.System.EventID.text
			desc = hit.Event.Description.short.strip()
			channel = hit.Event.System.Channel.strip()
			sid = hit.Event.System.Security.UserID.strip()
			# Specific
			process = hit.Event.EventData.Data.NewProcessName
			pid = hit.Event.EventData.Data.NewProcessId
			ppid = hit.Event.EventData.Data.ProcessId
			logon_id = hit.Event.EventData.Data.SubjectLogonId
			logon_domain = hit.Event.EventData.Data.SubjectDomainName
			logon_account = hit.Event.EventData.Data.SubjectUserName
			logon_sid = hit.Event.EventData.Data.SubjectUserSid

			# Todo : get end of process ? for handling depth
			child = Process(computer, process, pid, ppid, timestamp, None, logon_id, logon_domain, logon_account, logon_sid)
			self.childs[child.uid()] = child
			
		return self.childs

class ProcessStat(ElasticScenario):
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
		parser.add_argument('--batch_filter')
		parser.add_argument('--process_name', required=False, help='Filter on field Event.EventData.Data.NewProcessName (ie: powershell.exe)')
		parser.add_argument('--logon_id', required=False, help='Filter on logon Session ID (ie: 0x000000004e9f7608)')
		parser.add_argument('--username', required=False, help='Filter on logon username (ie: plop)')
		parser.add_argument('--system', required=False, help='Filter on system name (ie: plop-desktop)')
		parser.add_argument('--_from', required=False, help='YYYY-MM-DDTHH:MM:SS')
		parser.add_argument('--_to', required=False, help='YYYY-MM-DDTHH:MM:SS')
		parser.add_argument('--filter', required=False, help='Custom filter "Event.EventData.Data.SubjectUserName.keyword:plop"')

	def process(self):
		processes_search =  MultiMatch(query='4688', fields=[FIELD_EVENTID])
		if self.args.system:
			processes_search = processes_search & MultiMatch(query=self.args.system, fields=['Event.System.Computer'])
		if self.args.username:
			processes_search = processes_search & MultiMatch(query=self.args.username, fields=['Event.EventData.Data.SubjectUserName.keyword'])
		if self.args.logon_id:
			processes_search = processes_search & MultiMatch(query=self.args.logon_id, fields=['Event.EventData.Data.SubjectLogonId.keyword'])
		if self.args.process_name:
			processes_search = processes_search & MultiMatch(query=self.args.process_name, fields=['Event.EventData.Data.NewProcessName'])
		if self.args.batch_filter:
			processes_search = processes_search & MultiMatch(query=self.args.batch_filter, fields=['batch_id.keyword'])
		if self.args._from and self.args._to:
			processes_search = processes_search & Range(** {'@timestamp': {'gte': self.args._from, 'lte': self.args._to}})

		logging.info(' => query: {}'.format(processes_search))
		self.search =self.search.query(processes_search)


		self.search.aggs.bucket('computer', A('terms', field='Event.System.Computer.keyword'))\
		.bucket('username', 'terms', field='Event.EventData.Data.SubjectUserName.keyword')\
		.bucket('logon_id', 'terms', field='Event.EventData.Data.SubjectLogonId.keyword')\
		.metric('first_process', 'min', field='Event.System.TimeCreated.SystemTime')\
		.metric('last_process', 'max', field='Event.System.TimeCreated.SystemTime')
		self.resp = self.search.execute()

		print( ' {:_^30}_{:_^42}_{:_^30}_{:_^15}_{:_^30}_{:_^30}'.format('', '', '', '', '', '') )
		print( '|{: ^30}|{: ^42}|{: ^30}|{: ^15}|{: ^30}|{: ^30}|'.format('System', 'UserName', 'Session ID', 'Nb Process', 'First Process', 'Last Process') )
		print( ' {:_^30}_{:_^42}_{:_^30}_{:_^15}_{:_^30}_{:_^30}'.format('', '', '', '', '', '') )
		for computer_data in self.resp.aggregations.computer:
			for username_data in computer_data.username:
				for logon_id_data in username_data.logon_id:
					print( '|{: ^30}|{: ^42}|{: ^30}|{: ^15}|{: ^30}|{: ^30}|'.format(computer_data.key.split('.')[0], username_data.key, logon_id_data.key, logon_id_data.doc_count, logon_id_data.first_process.value_as_string, logon_id_data.last_process.value_as_string) )
		print( ' {:_^30}_{:_^42}_{:_^30}_{:_^15}_{:_^30}_{:_^30}'.format('', '', '', '', '', '') )


class ProcessTree(ElasticScenario):
	def __init__(self):
		super(ProcessTree, self).__init__()

	def add_argument(self, parser):
		super(ProcessTree, self).add_argument(parser)
		parser.add_argument('--batch_filter')
		parser.add_argument('--process_name', required=False, help='Filter on field Event.EventData.Data.NewProcessName (ie: powershell.exe)')
		parser.add_argument('--logon_id', required=False, help='Filter on logon Session ID (ie: 0x000000004e9f7608)')
		parser.add_argument('--username', required=False, help='Filter on logon username (ie: plop)')
		parser.add_argument('--system', required=False, help='Filter on system name (ie: plop-desktop)')
		parser.add_argument('--_from', required=False, help='YYYY-MM-DDTHH:MM:SS')
		parser.add_argument('--_to', required=False, help='YYYY-MM-DDTHH:MM:SS')
		parser.add_argument('--process_with_child_only', action='store_true', help='only prints processes that have childs')

	def find_all_possible_exit_points(self, process_list, max_query_size=100):

		exit_points = {}

		exit_query = MultiMatch(query='4689', fields=[FIELD_EVENTID])
		sub_queries = []
		for current_process in process_list:
			sub_q = MultiMatch(query=current_process.pid, fields=['Event.EventData.Data.ProcessId.keyword']) \
				& MultiMatch(query=current_process.system, fields=['Event.System.Computer.keyword']) \
				& MultiMatch(query=current_process.logon_id, fields=['Event.EventData.Data.SubjectLogonId.keyword']) \
				& MultiMatch(query=current_process.image_path, fields=['Event.EventData.Data.ProcessName.keyword'])

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
				# Generic
				computer = hit.Event.System.Computer
				timestamp = hit.Event.System.TimeCreated.SystemTime
				eventid = hit.Event.System.EventID.text
				desc = hit.Event.Description.short.strip()
				channel = hit.Event.System.Channel.strip()
				sid = hit.Event.System.Security.UserID.strip()

				process = hit.Event.EventData.Data.ProcessName
				pid = hit.Event.EventData.Data.ProcessId
				
				logon_id = hit.Event.EventData.Data.SubjectLogonId
				logon_domain = hit.Event.EventData.Data.SubjectDomainName
				logon_account = hit.Event.EventData.Data.SubjectUserName
				logon_sid = hit.Event.EventData.Data.SubjectUserSid

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
		processes_search =  MultiMatch(query='4688', fields=[FIELD_EVENTID])
		if self.args.system:
			processes_search = processes_search & MultiMatch(query=self.args.system, fields=['Event.System.Computer'])
		if self.args.username:
			processes_search = processes_search & MultiMatch(query=self.args.username, fields=['Event.EventData.Data.SubjectUserName.keyword'])
		if self.args.logon_id:
			processes_search = processes_search & MultiMatch(query=self.args.logon_id, fields=['Event.EventData.Data.SubjectLogonId.keyword'])
		if self.args.process_name:
			processes_search = processes_search & MultiMatch(query=self.args.process_name, fields=['Event.EventData.Data.NewProcessName'])
		if self.args.batch_filter:
			processes_search = processes_search & MultiMatch(query=self.args.batch_filter, fields=['batch_id.keyword'])
		if self.args._from and self.args._to:
			processes_search = processes_search & Range(** {'@timestamp': {'gte': self.args._from, 'lte': self.args._to}})

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
			# Generic
			computer = hit.Event.System.Computer
			timestamp = hit.Event.System.TimeCreated.SystemTime
			eventid = hit.Event.System.EventID.text
			desc = hit.Event.Description.short.strip()
			channel = hit.Event.System.Channel.strip()
			sid = hit.Event.System.Security.UserID.strip()
			# Specific
			process = hit.Event.EventData.Data.NewProcessName
			pid = hit.Event.EventData.Data.NewProcessId
			ppid = hit.Event.EventData.Data.ProcessId
			logon_id = hit.Event.EventData.Data.SubjectLogonId
			logon_domain = hit.Event.EventData.Data.SubjectDomainName
			logon_account = hit.Event.EventData.Data.SubjectUserName
			logon_sid = hit.Event.EventData.Data.SubjectUserSid

			# Create process object (missing the end date...)
			current_process = Process(computer, process, pid, ppid, timestamp, None, logon_id, logon_domain, logon_account, logon_sid)
			PROCESS_ALL.append(current_process)

		#
		#  2 - For each process, search the exit point
		#

		exit_points = self.find_all_possible_exit_points(PROCESS_ALL)
		for current_process in PROCESS_ALL:
			current_process.find_exit(exit_points)

		#
		#  3 - Find childs
		#

		cpt = 0
		for current_process in PROCESS_ALL:
		# for current_process in PROCESS_VALID:
			cpt += 1
			logging.info('Computing childs: {}/{}'.format(cpt, len(PROCESS_ALL)))			
			for child_uid in current_process.get_childs(Search(using=self.client, index=self.index)).keys():
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
		#  4 - Print !!!
		#

		root_processes = [process for uid, process in PROCESS_TREE.items()]
		for process in sorted(root_processes, key=lambda process: process.begin):
			if not self.args.process_with_child_only or len(process.childs) > 0:
				print(process.pretty_print(details=True))
				
