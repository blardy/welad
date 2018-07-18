# -*- coding: utf-8 -*-

from elasticsearch_dsl.query import MultiMatch
from scenario.scenario import ElasticScenario

"""
	All scenarios related about logon / logoff activities
"""

class LogonHistory(ElasticScenario):
	help = 'Extract logon history'

	LOGON_SUBSTATUS = {
		'0xc0000064' : 'user name does not exist',
		'0xc000006a' : 'user name is correct but the password is wrong',
		'0xc0000234' : 'user is currently locked out',
		'0xc0000072' : 'account is currently disabled',
		'0xc000006f' : 'user tried to logon outside his day of week or time of day restrictions',
		'0xc0000070' : 'workstation restriction, or Authentication Policy Silo violation (look for event ID 4820 on domain controller)',
		'0xc0000193' : 'account expiration',
		'0xc0000071' : 'expired password',
		'0xc0000133' : 'clocks between DC and other computer too far out of sync',
		'0xc0000224' : 'user is required to change password at next logon',
		'0xc0000225' : 'evidently a bug in Windows and not a risk',
		'0xc000015b' : 'The user has not been granted the requested logon type (aka logon right) at this machine',
	}

	def process(self):
		# 4624 + 4625
		sec_logon = (MultiMatch(query='4624', fields=['event.System.EventID.content']) | MultiMatch(query='4625', fields=['event.System.EventID.content'])) & MultiMatch(query='Security', fields=['event.System.Channel.keyword'])
		# RDP
		rdp_logon = (MultiMatch(query='21', fields=['event.System.EventID.content']) | MultiMatch(query='25', fields=['event.System.EventID.content']) ) & \
			MultiMatch(query='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational', fields=['event.System.Channel.keyword'])

		self.search = self.search.query(rdp_logon | sec_logon)
		self.resp = self.search.execute()

		print('Having {} of events:'.format(self.resp.hits.total))
		for hit in self.search.scan():
			header = '[{}][{}][{}] - '.format(hit['@timestamp'], hit.event.System.Computer, hit.event.System.EventID.content)

			if hit.event.System.EventID.content == '21':
				print('{}Successful connection of {} from {}'.format(header, hit.event.UserData.EventXML.User, hit.event.UserData.EventXML.Address))
			if hit.event.System.EventID.content == '25':
				print('{}Successful reconnection of {} from {}'.format(header, hit.event.UserData.EventXML.User, hit.event.UserData.EventXML.Address))
			if hit.event.System.EventID.content == '4624':
				print('{}Successful connection (type {}) of {}\\{} from {} ({}) with LogonProcess {} ({})'.format(header, hit.event.EventData.LogonType, hit.event.EventData.TargetDomainName, hit.event.EventData.TargetUserName, hit.event.EventData.IpAddress, hit.event.EventData.WorkstationName, hit.event.EventData.LogonProcessName, hit.event.EventData.ProcessName))
			if hit.event.System.EventID.content == '4625':
				print('{}Fail connection (type {} - {}) of {}\\{} from {} ({}) with LogonProcess {} ({})'.format(header, hit.event.EventData.LogonType, LogonHistory.LOGON_SUBSTATUS.get(hit.event.EventData.SubStatus.lower(), hit.event.EventData.SubStatus.lower()),  hit.event.EventData.TargetDomainName, hit.event.EventData.TargetUserName, hit.event.EventData.IpAddress, hit.event.EventData.WorkstationName, hit.event.EventData.LogonProcessName, hit.event.EventData.ProcessName))
				

		

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