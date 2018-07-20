# -*- coding: utf-8 -*-

from elasticsearch_dsl.query import MultiMatch
from scenario.scenario import ElasticScenario

import json
import copy

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
		sec_logon = (MultiMatch(query='4624', fields=['event.System.EventID.content']) | MultiMatch(query='4625', fields=['event.System.EventID.content'])) & MultiMatch(query='Security', fields=['event.System.Channel.keyword'])
		self.search = self.search.query(sec_logon)
		self.resp = self.search.execute()

		print('Total hits: {}'.format(self.resp.hits.total))

		process = set()
		"""
		  Total sucessful connections:
		  Total Failed connections:
		  Process used for logon:
		  	- XXXXX : XX connections
		  	- XXXXX : XX connections
		  	- XXXXX : XX connections
		  Account used for logon:
		  	- ACOUNT | FIRST TIME | LAST TIME | NB_CO | IPs | NB_FAIL | NB_SUCCESS
		"""
		stat_per_comp = {
			'success' : 0,
			'fail' : 0,
			'process' : {},
			'account' : {}
		}

		stat_per_account = {
			'first_seen' : None,
			'last_seen' : None,
			'nb_connections' : 0,
			'nb_fail' : 0,
			'ips' : {}
		}
		stats = {}


		print('==========================================================')
		print('===  Warning this is only based on 4624 and 4625 events ==')
		print('==========================================================')

		for hit in self.search.scan():
			stat = stats.get(hit.event.System.Computer, copy.deepcopy(stat_per_comp))
			
			account_name = '{}\\{}'.format(hit.event.EventData.TargetDomainName, hit.event.EventData.TargetUserName)
			acc = stat['account'].get(account_name, copy.deepcopy(stat_per_account))
			acc['nb_connections'] = acc['nb_connections'] + 1
			nb_co = acc['ips'].get(hit.event.EventData.IpAddress, 0)
			acc['ips'][hit.event.EventData.IpAddress] = nb_co + 1

			evt_date = hit['@timestamp']
			if not acc['first_seen']:
				acc['first_seen'] = evt_date
				acc['last_seen'] = evt_date
			else:
				acc['first_seen'] = min(evt_date, acc['first_seen'])
				acc['last_seen'] = max(evt_date, acc['last_seen'])

			if hit.event.System.EventID.content == '4624':
				stat['success'] = stat['success'] + 1
			if hit.event.System.EventID.content == '4625':
				acc['nb_fail'] = acc['nb_fail'] + 1				
				stat['fail'] = stat['fail'] + 1

			if 'ProcessName' in hit.event.EventData:
				proc_stat = stat['process'].get(hit.event.EventData.ProcessName, 0)
				stat['process'][hit.event.EventData.ProcessName] = proc_stat + 1

			stat['account'][account_name] = acc
			stats[hit.event.System.Computer] = stat

		

		for computer, stat in stats.items():
			print('======= Logon Stats for {} ======='.format(computer))
			accounts = stat['account']
			stat['account'] = None
			print(json.dumps(stats, indent = 2))
			header = ['Name', 'First Seen', 'Last Seen', 'Total Connections', 'IPs', 'Nb Fail']
			print('|'.join(header))
			for account, acc_stat in accounts.items():
				print('|'.join([account, acc_stat['first_seen'], acc_stat['last_seen'], acc_stat['nb_connections'], ';'.join(acc_stat['ips'].keys()),  acc_stat['nb_fail'] ] ))


