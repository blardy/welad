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


		blacklist = self.get_conf('blacklist', default=[])
		blacklist_filter = None
		if blacklist:
			blacklist_filter = MultiMatch(query=blacklist[0])
			for keyword in blacklist[1:]:
				blacklist_filter = blacklist_filter | MultiMatch(query=keyword)

		self.alert.init(['Date / Time (UTC)', 'Computer Name', 'Case', 'Channel', 'EventID', 'Description (short)', 'Service Name', 'SID', 'Payload Analysis', 'IP', 'Port', 'Payload (Raw)', 'Payload (Decoded)'])
		
		# Powershell Exec evidence
		#services = MultiMatch(query='Windows PowerShell', fields=[self.get_mapping('evt_channel_field_k')]) & (MultiMatch(query='-noni') | MultiMatch(query='-nop -w hidden') | MultiMatch(query='COMSPEC') )
		services = MultiMatch(query='Windows PowerShell', fields=[self.get_mapping('evt_channel_field_k')]) & ( blacklist_filter )
		if self.filter:
			services &= self.filter	
		self.search =self.search.query(services)
		self.resp = self.search.execute()

		for hit in self.search.scan():
			d_hit = hit.to_dict()
			# Generic fields
			computer = self.get_value(d_hit, self.get_mapping('evt_system_field'))
			timestamp = self.get_value(d_hit, self.get_mapping('evt_time_field'))
			event_id = self.get_value(d_hit, self.get_mapping('evt_event_id_field'))
			desc = self.get_value(d_hit, self.get_mapping('evt_desc_field'))
			case = self.get_value(d_hit, self.get_mapping('case_field'))

			channel = self.get_value(d_hit, self.get_mapping('evt_channel_field'))
			sid = '-'
			if event_id == 7045:
				continue

			# Extract payload from Powershell raw data
			logging.debug(event_id)
			logging.debug(hit.message)
			logging.debug(self.get_value(d_hit, self.get_mapping('evt_powershell_rawdata_field')))
			logging.debug([x for x in self.get_value(d_hit, self.get_mapping('evt_powershell_rawdata_field')).split('\n') if 'HostApplication=' in x])
			logging.debug('===================================')
			payload = [x for x in self.get_value(d_hit, self.get_mapping('evt_powershell_rawdata_field')).split('\n') if 'HostApplication=' in x]
			if not payload:
				[x for x in self.get_value(d_hit, self.get_mapping('evt_powershell_rawdata_2_field')).split('\n') if 'HostApplication=' in x]
			_payload = ''
			if payload:
				_payload = payload[0].strip().replace('HostApplication=', '')

			# TODO: decode paylaod
			mess, ip, port = 'unknown', '', ''
			is_decoded, decoded_payload  = '', ''

			self.alert.add_alert([timestamp, computer, case, channel, event_id, desc, '-', sid, mess, ip, port, _payload, decoded_payload])

		# Service Creation evidence
		services = MultiMatch(query=7045, fields=[self.get_mapping('evt_event_id_field')]) & ( blacklist_filter )
		search = Search(using=self.client, index=self.index)
		if self.filter:
			services &= self.filter

		search = search.query(services)

		resp = search.execute()
		for hit in search.scan():
			d_hit = hit.to_dict()
			# Generic fields
			computer = self.get_value(d_hit, self.get_mapping('evt_system_field'))
			timestamp = self.get_value(d_hit, self.get_mapping('evt_time_field'))
			event_id = self.get_value(d_hit, self.get_mapping('evt_event_id_field'))
			desc = self.get_value(d_hit, self.get_mapping('evt_desc_field'))
			case = self.get_value(d_hit, self.get_mapping('case_field'))
			channel = self.get_value(d_hit, self.get_mapping('evt_channel_field'))

			sid = self.get_value(d_hit, self.get_mapping('evt_user_sid_field'))
			servicename = self.get_value(d_hit, self.get_mapping('evt_service_name_field'))
			payload = self.get_value(d_hit, self.get_mapping('evt_service_path_field'))

			mess, ip, port = 'unknown', '', ''
			decoded_payload = ''
			# is_decoded, decoded_payload = decode_powershell(payload)
			# if is_decoded:
			# 	mess, ip, port = analyze_payload(decoded_payload)

			self.alert.add_alert([timestamp, computer, case, channel, event_id, desc,servicename, sid,  mess, ip, port, payload, decoded_payload])

		# 4697
		services = MultiMatch(query='4697', fields=[self.get_mapping('evt_event_id_field')]) & ( blacklist_filter )
		search = Search(using=self.client, index=self.index)
		if self.filter:
			services &= self.filter
		search = search.query(services)
		
		resp = search.execute()
		for hit in search.scan():
			d_hit = hit.to_dict()
			# Generic fields
			computer = self.get_value(d_hit, self.get_mapping('evt_system_field'))
			timestamp = self.get_value(d_hit, self.get_mapping('evt_time_field'))
			event_id = self.get_value(d_hit, self.get_mapping('evt_event_id_field'))
			desc = self.get_value(d_hit, self.get_mapping('evt_desc_field'))
			case = self.get_value(d_hit, self.get_mapping('case_field'))
			channel = self.get_value(d_hit, self.get_mapping('evt_channel_field'))
			sid = self.get_value(d_hit, self.get_mapping('evt_service_sid'))

			servicename = self.get_value(d_hit, self.get_mapping('evt_service_name_field'))
			payload = self.get_value(d_hit, self.get_mapping('evt_service_filename_field'))

			mess, ip, port = 'unknown', '', ''
			is_decoded, decoded_payload = decode_powershell(payload)
			if is_decoded:
				mess, ip, port = analyze_payload(decoded_payload)

			self.alert.add_alert([timestamp, computer, case, channel, eventid, desc,servicename, sid,  mess, ip, port, payload, decoded_payload])
	
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

