# -*- coding: utf-8 -*-

from elasticsearch_dsl.query import MultiMatch, Range
from elasticsearch_dsl import A
from scenario.scenario import *


import logging


"""
	OPTIM:
		+ ProcessTree
			- Change how the process tree is build as it is slow... and it is doing much queries...
				+ First query to get 4688 event with filters
				+ based on this one do one or more queries to get the end of process (using OR with process id...) => should at least be able to get 10 by 10...
				 => Construct child based on the process we ave seen AND not using another queries....
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
		child_query = MultiMatch(query='4688', fields=[FIELD_EVENTID]) \
			& MultiMatch(query=self.system, fields=['Event.System.Computer.keyword']) \
			& MultiMatch(query=self.pid, fields=['Event.EventData.Data.ProcessId.keyword']) \
			& Range(** {'@timestamp': {'gte': self.begin, 'lte': self.end}})

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

		# Todo: Global query to get all exit point ==> only 1 query to ES
		#   And then stored it on hashmap by [system][logon_id][pid][imagepath]['processes'] = [EXIT_P1, EXIT_P2, EXIT_P3....]
		#   GO over eahc process and lok for exit point on hasmap.

		SESSION_ID = {}
		SESSION_ID_VALID = {}
		process_with_no_end = 0
		process_with_too_many_end = 0
		cpt = 0
		for current_process in PROCESS_ALL:
			cpt += 1
			logging.info('Finding end of processes: {}/{}'.format(cpt,len(PROCESS_ALL)))

			count = SESSION_ID.get(current_process.logon_id, 0)
			SESSION_ID[current_process.logon_id] = count + 1

			# Search for  the end of teh process	
			exit_search = Search(using=self.client, index=self.index)
			exit_processes_search = MultiMatch(query='4689', fields=[FIELD_EVENTID]) \
				& MultiMatch(query=current_process.pid, fields=['Event.EventData.Data.ProcessId.keyword']) \
				& MultiMatch(query=current_process.system, fields=['Event.System.Computer.keyword']) \
				& MultiMatch(query=current_process.logon_id, fields=['Event.EventData.Data.SubjectLogonId.keyword']) \
				& MultiMatch(query=current_process.image_path, fields=['Event.EventData.Data.ProcessName.keyword'])
			exit_search = exit_search.query(exit_processes_search)
			exit_processes_resp = exit_search.execute()

			if not exit_processes_resp.hits.total:
				logon_id_unk_process = PROCESS_NO_EXIT.get(logon_id, [])
				logon_id_unk_process.append(current_process)
				PROCESS_NO_EXIT[logon_id] = logon_id_unk_process
				process_with_no_end += 1
			elif exit_processes_resp.hits.total > 1:
				logon_id_unk_process = PROCESS_TOO_MANY_EXIT.get(logon_id, [])
				logon_id_unk_process.append(current_process)
				PROCESS_TOO_MANY_EXIT[logon_id] = logon_id_unk_process
				process_with_too_many_end += 1
			else:
				exit_point = exit_processes_resp[0]
				end_date = exit_point.Event.System.TimeCreated.SystemTime
				current_process.end = end_date
				PROCESS_VALID.append(current_process)

				count = SESSION_ID_VALID.get(current_process.logon_id, 0)
				SESSION_ID_VALID[current_process.logon_id] = count + 1


		#
		#  3 - Some warning about processes that were skipped during proces...
		#
		logging.warning('')
		logging.warning('==========================================================================')
		logging.warning('   - Found {} valid processes in {} different SessionID'.format(len(PROCESS_VALID), len(SESSION_ID_VALID.keys())))
		logging.warning('   - Found {} processes with no end'.format(process_with_no_end))
		logging.warning('      - Those were found on {} Sessions: {}'.format(len(PROCESS_NO_EXIT.keys()), PROCESS_NO_EXIT.keys()))
		logging.warning('   - Found {} processes with too many end'.format(process_with_too_many_end))
		logging.warning('      - Those were found on {} Sessions: {}'.format(len(PROCESS_TOO_MANY_EXIT.keys()), PROCESS_TOO_MANY_EXIT.keys()))
		logging.warning('==========================================================================')
		logging.warning('')
		#
		#  4 - Find child for Valid processes
		#

		# End loop
		cpt = 0
		for current_process in PROCESS_VALID:
			cpt += 1
			logging.info('Computing childs: {}/{}'.format(cpt, len(PROCESS_VALID)))			
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

		root_processes = [process for uid, process in PROCESS_TREE.items()]
		for process in sorted(root_processes, key=lambda process: process.begin):
			if not self.args.process_with_child_only or len(process.childs) > 0:
				print(process.pretty_print(details=True))
				
