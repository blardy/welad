# -*- coding: utf-8 -*-

from elasticsearch_dsl.query import MultiMatch, Range
from elasticsearch_dsl import A
from scenario.scenario import *
from scenario.utils import *

from urllib.parse import urlparse

import json
import re
import base64
import gzip
import binascii


"""
	Services related scenarios
"""
class MaliciousPowerShell(ElasticScenario):
	help = 'Search for malicious powershell in services / powershell events'

	def __init__(self):
		super(MaliciousPowerShell, self).__init__()

	def add_argument(self, parser):
		super(MaliciousPowerShell, self).add_argument(parser)

	def process(self):
		
		services = MultiMatch(query='Windows PowerShell', fields=['Event.System.Channel.keyword']) & (MultiMatch(query='-noni') | MultiMatch(query='-nop -w hidden') | MultiMatch(query='COMSPEC') )

		if self.filter:
			services &= self.filter
			
		self.search =self.search.query(services)
		self.resp = self.search.execute()

		self.alert.init(['Date / Time (UTC)', 'Computer Name', 'Channel', 'EventID', 'Description (short)', 'Service Name', 'SID', 'Payload Analysis', 'IP', 'Port', 'Payload (Raw)', 'Payload (Decoded)'])

		for hit in self.search.scan():
			computer = hit.Event.System.Computer
			timestamp = hit.Event.System.TimeCreated.SystemTime
			eventid = hit.Event.System.EventID.text
			desc = hit.Event.Description.short.strip()
			channel = hit.Event.System.Channel.strip()
			sid = hit.Event.System.Security.UserID.strip()
			if eventid == '7045':
				continue

			try:
				try:
					payload = [x for x in hit.Event.EventData.RawData.split('\n') if 'HostApplication=' in x][0]
					_payload = payload.strip().replace('HostApplication=', '')
				except:
					payload = hit.Event.EventData.Data.ImagePath
					_payload = payload.strip()
			except:
				continue


			
			mess, ip, port = 'unknown', '', ''
			is_decoded, decoded_payload = decode_powershell(payload)
			if is_decoded:
				mess, ip, port = analyze_payload(decoded_payload)

			self.alert.add_alert([timestamp, computer, channel, eventid, desc, '-', sid, mess, ip, port, _payload, decoded_payload])

		services = MultiMatch(query='7045', fields=[FIELD_EVENTID]) & ( MultiMatch(query='COMSPEC') | MultiMatch(query='if') |  MultiMatch(query='encodedcommand') |  MultiMatch(query='echo'))
		search = Search(using=self.client, index=self.index)
		if self.filter:
			services &= self.filter

		search = search.query(services)

		resp = search.execute()
		for hit in search.scan():
			computer = hit.Event.System.Computer
			timestamp = hit['@timestamp']
			eventid = hit.Event.System.EventID.text.strip()
			desc = hit.Event.Description.short.strip()
			channel = hit.Event.System.Channel.strip()
			sid = hit.Event.System.Security.UserID.strip()
			servicename = hit.Event.EventData.Data.ServiceName.strip()
			payload = hit.Event.EventData.Data.ImagePath.strip()

			mess, ip, port = 'unknown', '', ''
			is_decoded, decoded_payload = decode_powershell(payload)
			if is_decoded:
				mess, ip, port = analyze_payload(decoded_payload)

			self.alert.add_alert([timestamp, computer, channel, eventid, desc,servicename, sid,  mess, ip, port, payload, decoded_payload])

		services = MultiMatch(query='4697', fields=[FIELD_EVENTID]) & ( MultiMatch(query='COMSPEC') | MultiMatch(query='if') |  MultiMatch(query='encodedcommand') |  MultiMatch(query='echo'))
		search = Search(using=self.client, index=self.index)

		if self.filter:
			services &= self.filter

		search = search.query(services)

		resp = search.execute()
		for hit in search.scan():
			computer = hit.Event.System.Computer
			timestamp = hit['@timestamp']
			eventid = hit.Event.System.EventID.text.strip()
			desc = hit.Event.Description.short.strip()
			channel = hit.Event.System.Channel.strip()
			sid = hit.Event.EventData.Data.SubjectUserSid.strip()
			servicename = hit.Event.EventData.Data.ServiceName.strip()
			payload = hit.Event.EventData.Data.ServiceFileName.strip()

			mess, ip, port = 'unknown', '', ''
			is_decoded, decoded_payload = decode_powershell(payload)
			if is_decoded:
				mess, ip, port = analyze_payload(decoded_payload)

			self.alert.add_alert([timestamp, computer, channel, eventid, desc,servicename, sid,  mess, ip, port, payload, decoded_payload])


			

"""
	Extract BITS (Background Intelligent Transfer Service) URLs
		Event 59 - BITS started the BITS Transfer transfer job
		Event 60 - BITS stopped transferring the BITS Transfer transfer job 
		Event 61 - BITS stopped transferring the BITS Transfer transfer job wth error code
"""
class BITSService(ElasticScenario):
	def __init__(self):
		super(BITSService, self).__init__()

	def process(self):
		bits_service = (MultiMatch(query='59', fields=[FIELD_EVENTID]) | MultiMatch(query='60', fields=[FIELD_EVENTID]) | MultiMatch(query='61', fields=[FIELD_EVENTID]) ) \
			& MultiMatch(query='Microsoft-Windows-Bits-Client/Operational', fields=[FIELD_CHANNEL])

		if self.filter:
			bits_service &= self.filter

		self.search = self.search.query(bits_service)
		self.search.aggs.bucket('computer', 'terms', field='Event.System.Computer.keyword', size = self.bucket_size)\
			.bucket('bits', 'terms', field='Event.EventData.Data.url.keyword', size = self.bucket_size)


		self.alert.init(['Computer Name', 'Location', 'Path', 'Params', 'Query', 'Nb Hits'])
		self.resp = self.search.execute()
		for computer_data in self.resp.aggregations.computer:
			for bits_data in computer_data.bits:
				url = urlparse(bits_data.key)
				self.alert.add_alert([computer_data.key, '{}://{}'.format(url.scheme, url.netloc) if url.netloc else url.geturl(), url.path, url.params, url.query, bits_data.doc_count])

"""
	Should be done using aggregation !
	  Event 7036 - The <service name> service entered the <running/stopped> state.
	  	Event.EventData.Data.param1  => ServiceName
	  	Event.EventData.Data.param2  => running / stopped
	  Event 7040 - The start type of the <service> service was changed from disabled to auto start.
	  	Event.EventData.Data.param1
	  	Event.EventData.Data.param2
	  	Event.EventData.Data.param3
	  	Event.EventData.Data.param4 
	  Event 7045 - A service was installed in the system.
	  	Event.EventData.Data.ServiceName      	
	  	Event.EventData.Data.ServiceType      	
	  	Event.EventData.Data.StartType
"""


# class StatServices(ElasticScenario):
# 	help = 'Extract stats about services'

# 	def __init__(self):
# 		super(StatServices, self).__init__()

# 	def process(self):
# 		services = MultiMatch(query='7036', fields=[FIELD_EVENTID]) & MultiMatch(query='System', fields=[FIELD_CHANNEL])
# 		self.search = self.search.query(services)
# 		self.resp = self.search.execute()

# 		print('Total service hits: {}'.format(self.resp.hits.total))

# 		services_stats = {}

# 		for hit in self.search.scan():
# 			svc_name = hit.Event.EventData.Data.param1
# 			svc_state = hit.Event.EventData.Data.param2
# 			evt_date = hit['@timestamp']

# 			stat = services_stats.get(svc_name, {})
# 			stat['first_seen'] = min(stat.get('first_seen', evt_date), evt_date)
# 			stat['last_seen'] = max(stat.get('last_seen', evt_date), evt_date)

# 			if svc_state == 'running':
# 				stat['nb_start'] = stat.get('nb_start', 0) + 1

# 			services_stats[svc_name] = stat


# 		header = ['Service Name', 'First Seen', 'Last Seen', 'nb_start']
# 		SEPARATOR = '|'
# 		print(SEPARATOR.join(header))
# 		for service, stat in services_stats.items():
# 			print(SEPARATOR.join([service, stat['first_seen'], stat['last_seen'], str(stat.get('nb_start', 0))]))

