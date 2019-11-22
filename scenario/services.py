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
#TODO: MaliciousPowerShell / update mapping
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

		self.alert.init(['Date / Time (UTC)', 'Computer Name', 'Tag', 'Channel', 'EventID', 'Description (short)', 'Service Name', 'SID', 'Payload Analysis', 'IP', 'Port', 'Payload (Raw)', 'Payload (Decoded)'])

		for hit in self.search.scan():
			computer = hit.Event.System.Computer
			timestamp = hit.Event.System.TimeCreated.SystemTime
			eventid = hit.Event.System.EventID.text
			try:
				desc = hit.Event.Description.short.strip()
			except:
				desc = ''
			try:
				tag = hit.tag.strip()
			except:
				tag = ''

			channel = hit.Event.System.Channel.strip()
			sid = hit.Event.System.Security.UserID.strip()
			if eventid == 7045:
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

			self.alert.add_alert([timestamp, computer, tag, channel, eventid, desc, '-', sid, mess, ip, port, _payload, decoded_payload])

		services = MultiMatch(query=7045, fields=[self.get_mapping('evt_event_id_field')]) & ( MultiMatch(query='COMSPEC') | MultiMatch(query='if') |  MultiMatch(query='encodedcommand') |  MultiMatch(query='echo'))
		#services = MultiMatch(query=7045, fields=[self.get_mapping('evt_event_id_field')]) & ( MultiMatch(query='COMSPEC', fields=['winlog.event_data.ImagePath']) )
		search = Search(using=self.client, index=self.index)
		if self.filter:
			services &= self.filter

		search = search.query(services)

		resp = search.execute()
		for hit in search.scan():
			computer = hit.winlog.computer_name
			d_hit = hit.to_dict()
			timestamp = d_hit.get('@timestamp')
			eventid = hit.event.code
			desc = hit.description.short.strip()
			channel = hit.winlog.channel.strip()
			sid = hit.winlog.user.identifier.strip()
			servicename = hit.winlog.event_data.ServiceName.strip()
			payload = hit.winlog.event_data.ImagePath.strip()
			tag = hit.case

			mess, ip, port = 'unknown', '', ''
			decoded_payload = ''
			# is_decoded, decoded_payload = decode_powershell(payload)
			# if is_decoded:
			# 	mess, ip, port = analyze_payload(decoded_payload)

			self.alert.add_alert([timestamp, computer, tag, channel, eventid, desc,servicename, sid,  mess, ip, port, payload, decoded_payload])

		services = MultiMatch(query='4697', fields=[self.get_mapping('evt_channel_field')]) & ( MultiMatch(query='COMSPEC') | MultiMatch(query='if') |  MultiMatch(query='encodedcommand') |  MultiMatch(query='echo'))
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
			try:
				tag = hit.tag.strip()
			except:
				tag = ''
			mess, ip, port = 'unknown', '', ''
			is_decoded, decoded_payload = decode_powershell(payload)
			if is_decoded:
				mess, ip, port = analyze_payload(decoded_payload)

			self.alert.add_alert([timestamp, computer, tag, channel, eventid, desc,servicename, sid,  mess, ip, port, payload, decoded_payload])
	
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
		bits_service = (MultiMatch(query='59', fields=[self.get_mapping('evt_event_id_field')]) | MultiMatch(query='60', fields=self.get_mapping('evt_event_id_field')) | MultiMatch(query='61', fields=self.get_mapping('evt_event_id_field'))) \
			& MultiMatch(query='Microsoft-Windows-Bits-Client/Operational', fields=self.get_mapping('evt_channel_field_k'))

		if self.filter:
			bits_service &= self.filter

		self.search = self.search.query(bits_service)

		self.search.aggs.bucket('computer', 'terms', field=self.get_mapping('evt_system_field_k'), size = self.bucket_size)\
			.bucket('bits', 'terms', field=self.get_mapping('evt_bits_url_field_k'), size = self.bucket_size)


		self.alert.init(['Computer Name', 'Location', 'Path', 'Params', 'Query', 'Nb Hits'])
		self.resp = self.search.execute()
		for computer_data in self.resp.aggregations.computer:
			for bits_data in computer_data.bits:
				url = urlparse(bits_data.key)
				self.alert.add_alert([computer_data.key, '{}://{}'.format(url.scheme, url.netloc) if url.netloc else url.geturl(), url.path, url.params, url.query, bits_data.doc_count])

