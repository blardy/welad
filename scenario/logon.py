# -*- coding: utf-8 -*-

from elasticsearch_dsl.query import MultiMatch
from scenario.scenario import *

import json
import copy

"""
	All scenarios related about logon / logoff activities
"""

"""
	List all logon attempts
	  Can be verbose...
"""
class LogonHistory(ElasticScenario):
	help = 'Extract logon history'

	LOGON_TYPE = {
		'2' : 'Interactive',
		'3' : 'Network',
		'4' : 'Batch',
		'5' : 'Service',
		'7' : 'Unlock',
		'8' : 'NetworkCleartext',
		'9' : 'NewCredentials',
		'10' : 'RemoteInteractive',
		'11' : 'CachedInteractive',
	}

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
		# 4624 + 4625 logon
		sec_logon = (MultiMatch(query='4624', fields=[FIELD_EVENTID]) | MultiMatch(query='4625', fields=[FIELD_EVENTID])) \
			& MultiMatch(query='Security', fields=[FIELD_CHANNEL])
		# RDP logon
		rdp_logon = (MultiMatch(query='21', fields=[FIELD_EVENTID]) | MultiMatch(query='25', fields=[FIELD_EVENTID]) ) \
			& MultiMatch(query='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational', fields=[FIELD_CHANNEL])

		self.search = self.search.query(rdp_logon | sec_logon)
		self.resp = self.search.execute()

		for hit in self.search.scan():
			alert_data = OrderedDict()
			alert_data['SystemTime'] = hit.Event.System.TimeCreated.SystemTime
			alert_data['Computer'] = hit.Event.System.Computer
			alert_data['event_id'] = hit.Event.System.EventID.text
			alert_data['IpAddress'] = ''
			alert_data['TargetDomainName'] = ''
			alert_data['TargetUserName'] = ''
			alert_data['LogonType'] = ''
			alert_data['message'] = ''

			if alert_data['event_id'] == '21' or hit.Event.System.EventID.text == '25':					
				alert_data['IpAddress'] = hit.Event.UserData.EventXML.Address
				alert_data['TargetUserName'] = hit.Event.UserData.EventXML.User
				alert_data['LogonType'] = 'Remote Desktop'
				message = 'Successful connection' if alert_data['event_id'] == '21' else 'Successful reconnection'
				alert_data['message'] = message
			else:
				alert_data['IpAddress'] = hit.Event.EventData.Data.IpAddress
				alert_data['LogonType'] = LogonHistory.LOGON_TYPE.get(hit.Event.EventData.Data.LogonType, hit.Event.EventData.Data.LogonType)
				alert_data['TargetDomainName'] = hit.Event.EventData.Data.TargetDomainName
				alert_data['TargetUserName'] = hit.Event.EventData.Data.TargetUserName
				if alert_data['event_id'] == '4625':
					message = 'Fail connection - {}'.format(LogonHistory.LOGON_SUBSTATUS.get(hit.Event.EventData.Data.SubStatus.lower(), hit.Event.EventData.Data.SubStatus.lower()))
				else:
					message = 'Successful connection'
				alert_data['message'] = message

			alert = Alert(message = message, data=alert_data)
			self.alerts.append(alert)

"""
	Extract logon history from LocalSessionManager logs.
	 Event 21 (Remote Desktop Services: Session logon succeeded)
	 Event 25 (Remote Desktop Services: Session reconnection succeeded)
	    If Event.UserData.EventXML.Address field contains 'LOCAL': this means that it is not a RDP connection but an interactive logon.
"""
class RDPHistory(ElasticScenario):
	help = 'Extract logon history from LocalSessionManager logs'

	def process(self):
		rdp_logon = (MultiMatch(query='21', fields=[FIELD_EVENTID]) | MultiMatch(query='25', fields=[FIELD_EVENTID]) ) & \
			MultiMatch(query='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational', fields=[FIELD_CHANNEL])

		self.search = self.search.query(rdp_logon)
		self.resp = self.search.execute()

		for hit in self.search.scan():
			if hit.Event.System.EventID.text == '21' or hit.Event.System.EventID.text == '25':
				alert_data = OrderedDict()
				alert_data['SystemTime'] = hit.Event.System.TimeCreated.SystemTime
				alert_data['Computer'] = hit.Event.System.Computer
				alert_data['event_id'] = hit.Event.System.EventID.text
				alert_data['IpAddress'] = hit.Event.UserData.EventXML.Address
				alert_data['TargetUserName'] = hit.Event.UserData.EventXML.User
				message = 'Successful connection' if alert_data['event_id'] == '21' else 'Successful reconnection'
				alert_data['message'] = message

				alert = Alert(message = message, data=alert_data)
				self.alerts.append(alert)
		

class StatLogon(ElasticScenario):
	help = 'Extract stats about logon'

	def __init__(self):
		super(StatLogon, self).__init__()

	def process(self):
		sec_logon = (MultiMatch(query='4624', fields=[FIELD_EVENTID]) | MultiMatch(query='4625', fields=[FIELD_EVENTID])) & MultiMatch(query='Security', fields=[FIELD_CHANNEL])
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
			stat = stats.get(hit.Event.System.Computer, copy.deepcopy(stat_per_comp))
			
			account_name = '{}\\{}'.format(hit.Event.EventData.Data.TargetDomainName, hit.Event.EventData.Data.TargetUserName)
			acc = stat['account'].get(account_name, copy.deepcopy(stat_per_account))
			acc['nb_connections'] = acc['nb_connections'] + 1
			nb_co = acc['ips'].get(hit.Event.EventData.Data.IpAddress, 0)
			acc['ips'][hit.Event.EventData.Data.IpAddress] = nb_co + 1

			evt_date = hit.Event.System.TimeCreated.SystemTime
			if not acc['first_seen']:
				acc['first_seen'] = evt_date
				acc['last_seen'] = evt_date
			else:
				acc['first_seen'] = min(evt_date, acc['first_seen'])
				acc['last_seen'] = max(evt_date, acc['last_seen'])

			if hit.Event.System.EventID.text == '4624':
				stat['success'] = stat['success'] + 1
			if hit.Event.System.EventID.text == '4625':
				acc['nb_fail'] = acc['nb_fail'] + 1				
				stat['fail'] = stat['fail'] + 1

			if 'ProcessName' in hit.Event.EventData:
				proc_stat = stat['process'].get(hit.Event.EventData.Data.ProcessName, 0)
				stat['process'][hit.Event.EventData.Data.ProcessName] = proc_stat + 1

			stat['account'][account_name] = acc
			stats[hit.Event.System.Computer] = stat

		

		for computer, stat in stats.items():
			print('======= Logon Stats for {} ======='.format(computer))
			accounts = stat['account']
			stat['account'] = None
			print(json.dumps(stats, indent = 2))
			header = ['Name', 'First Seen', 'Last Seen', 'Total Connections', 'IPs', 'Nb Fail']
			print('|'.join(header))
			for account, acc_stat in accounts.items():
				print('|'.join([account, acc_stat['first_seen'], acc_stat['last_seen'], str(acc_stat['nb_connections']), ';'.join(acc_stat['ips'].keys()),  str(acc_stat['nb_fail']) ] ))


