# -*- coding: utf-8 -*-

from elasticsearch_dsl.query import MultiMatch, Range, Match
from elasticsearch_dsl import A
from scenario.scenario import *

import json
import copy


"""
	OPTIM:
		+ 

	SCENARIO:
		+ Stats
			- About logon
			- About failed logon
		+ Anomaly
			- IP that registered with several Workstation Name
			- User that connected from more than X workstation
			- User that connected to more than X workstation
"""

"""
	All scenarios related about logon / logoff activities
"""

class FailedLogonHistory(ElasticScenario):
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
		# 4625 logon
		sec_logon = (MultiMatch(query='4625', fields=[FIELD_EVENTID])) & MultiMatch(query='Security', fields=[FIELD_CHANNEL])

		if self.filter:
			sec_logon &= self.filter

		self.search = self.search.sort(self.evt_time_field)
		self.search = self.search.query(sec_logon)
		
		self.resp = self.search.execute()

		logging.info(  json.dumps(self.search.to_dict(), indent=2) )

		

		self.alert.init(['Date / Time (UTC)', 'Computer Name', 'Description', 'Logon Type', 'Domain\\User', 'IP Address', 'Workstion Name'])

		for hit in self.search.scan():
			computer = hit.Event.System.Computer
			timestamp = hit.Event.System.TimeCreated.SystemTime

			alert_data = {}
			alert_data['SystemTime'] = hit.Event.System.TimeCreated.SystemTime
			alert_data['Computer'] = hit.Event.System.Computer
			alert_data['event_id'] = hit.Event.System.EventID.text
			alert_data['IpAddress'] = ''
			alert_data['TargetDomainName'] = '.'
			alert_data['TargetUserName'] = ''
			alert_data['LogonType'] = ''
			alert_data['message'] = ''
			alert_data['WorkstationName'] = ''
			alert_data['IpAddress'] = hit.Event.EventData.Data.IpAddress
			alert_data['LogonType'] = LogonHistory.LOGON_TYPE.get(hit.Event.EventData.Data.LogonType, hit.Event.EventData.Data.LogonType)
			alert_data['TargetDomainName'] = hit.Event.EventData.Data.TargetDomainName
			alert_data['TargetUserName'] = hit.Event.EventData.Data.TargetUserName
			alert_data['WorkstationName'] = hit.Event.EventData.Data.WorkstationName
			alert_data['message'] = 'Fail connection - {}'.format(LogonHistory.LOGON_SUBSTATUS.get(hit.Event.EventData.Data.SubStatus.lower(), hit.Event.EventData.Data.SubStatus.lower()))

			self.alert.add_alert([timestamp, computer, alert_data['message'], alert_data['LogonType'], '{}\\{}'.format(alert_data['TargetDomainName'], alert_data['TargetUserName']), alert_data['IpAddress'], alert_data['WorkstationName'] ])



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

		query = (rdp_logon | sec_logon) 
		if self.filter:
			query &= self.filter


		self.search = self.search.query(query)
		self.resp = self.search.execute()
		logging.info(' => Total hits: : {}'.format(self.resp.hits.total))

		self.alert.init(['Date / Time (UTC)', 'Computer Name', 'Description', 'Logon Type', 'Domain\\User', 'IP Address', 'Workstion Name'])

		for hit in self.search.scan():
			computer = hit.Event.System.Computer
			timestamp = hit.Event.System.TimeCreated.SystemTime

			alert_data = {}
			alert_data['SystemTime'] = hit.Event.System.TimeCreated.SystemTime
			alert_data['Computer'] = hit.Event.System.Computer
			alert_data['event_id'] = hit.Event.System.EventID.text
			alert_data['IpAddress'] = ''
			alert_data['TargetDomainName'] = '.'
			alert_data['TargetUserName'] = ''
			alert_data['LogonType'] = ''
			alert_data['message'] = ''
			alert_data['WorkstationName'] = ''

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
				alert_data['WorkstationName'] = hit.Event.EventData.Data.WorkstationName
				if alert_data['event_id'] == '4625':
					message = 'Fail connection - {}'.format(LogonHistory.LOGON_SUBSTATUS.get(hit.Event.EventData.Data.SubStatus.lower(), hit.Event.EventData.Data.SubStatus.lower()))
				else:
					message = 'Successful connection'
				alert_data['message'] = message

			self.alert.add_alert([timestamp, computer, alert_data['message'], alert_data['LogonType'], '{}\\{}'.format(alert_data['TargetDomainName'], alert_data['TargetUserName']), alert_data['IpAddress'], alert_data['WorkstationName'] ])

"""
	Extract logon history from LocalSessionManager logs.
	 Event 21 (Remote Desktop Services: Session logon succeeded)
	 Event 25 (Remote Desktop Services: Session reconnection succeeded)
	    If Event.UserData.EventXML.Address field contains 'LOCAL': this means that it is not a RDP connection but an interactive logon.
"""
class RDPHistory(ElasticScenario):
	help = 'Extract logon history from LocalSessionManager logs'

	def process(self):
		rdp_logon = ( Match(Event__System__EventID__text__keyword='21') | Match(Event__System__EventID__text__keyword='25') ) & Match(Event__System__Channel__keyword='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational')
		rdp_logon |= ( Match(Event__System__EventID__text__keyword='1149') & Match(Event__System__Channel__keyword='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'))

		if self.filter:
			rdp_logon = (rdp_logon) & self.filter

		
		self.search = self.search.query(rdp_logon)
		logging.info(json.dumps(self.search.to_dict(), indent=2))
		self.resp = self.search.execute()

		self.alert.init(['Date / Time (UTC)', 'Computer Name', 'Description', 'Logon Type', 'Username', 'IP Address'])

		for hit in self.search.scan():
			computer = hit.Event.System.Computer
			timestamp = hit.Event.System.TimeCreated.SystemTime
			message = ''
			alert_data = {}
			alert_data['event_id'] = hit.Event.System.EventID.text

			if hit.Event.System.EventID.text == '21' or hit.Event.System.EventID.text == '25':
				alert_data['IpAddress'] = hit.Event.UserData.EventXML.Address
				alert_data['TargetUserName'] = hit.Event.UserData.EventXML.User
				message = 'Successful connection' if alert_data['event_id'] == '21' else 'Successful reconnection'
			else:
				alert_data['IpAddress'] = hit.Event.UserData.EventXML.Param3
				alert_data['TargetUserName'] = '{}\\{}'.format(hit.Event.UserData.EventXML.Param2, hit.Event.UserData.EventXML.Param1)
				message = 'Incoming connection'

			self.alert.add_alert([timestamp, computer, message, 'Remote Desktop', alert_data['TargetUserName'], alert_data['IpAddress']])


class LogonStat(ElasticScenario):
	help = 'Print stats about logon'

	def __init__(self):
		super(LogonStat, self).__init__()

	def process(self):
		sec_logon = (MultiMatch(query='4624', fields=[FIELD_EVENTID]) | MultiMatch(query='4625', fields=[FIELD_EVENTID])) & MultiMatch(query='Security', fields=[FIELD_CHANNEL])

		if self.filter:
			sec_logon = sec_logon & self.filter


		self.search = self.search.query(sec_logon)
		self.search.aggs.bucket('computer', 'terms', field='Event.System.Computer.keyword', size = self.bucket_size)\
			.bucket('username', 'terms', field='Event.EventData.Data.TargetUserName.keyword', size = self.bucket_size)\
			.bucket('logontype', 'terms', field='Event.EventData.Data.LogonType.keyword', size = self.bucket_size)\
			.bucket('eventid', 'terms', field='Event.System.EventID.text.keyword', size = self.bucket_size)\
			.bucket('ip', 'terms', field='Event.EventData.Data.IpAddress.keyword', size = self.bucket_size)\
			.bucket('source', 'terms', field='Event.EventData.Data.WorkstationName.keyword', size = self.bucket_size)\


		self.alert.init(['Computer Name', 'Username', 'Logon Type', 'Success / Failure', 'IP', 'Source Name', 'Count'])
		self.resp = self.search.execute()
		for computer_data in self.resp.aggregations.computer:
			for username_data in computer_data.username:
				for logontype_data in username_data.logontype:
					for eventid_data in logontype_data.eventid:
						for ip_data in eventid_data.ip:
							for source_data in ip_data.source:
								self.alert.add_alert([computer_data.key, username_data.key, LogonHistory.LOGON_TYPE.get(logontype_data.key, logontype_data.key), 'Success' if eventid_data.key == '4624' else 'Failure', ip_data.key, source_data.key, source_data.doc_count])

