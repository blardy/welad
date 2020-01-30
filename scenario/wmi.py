# -*- coding: utf-8 -*-

from elasticsearch_dsl.query import MultiMatch, Range
from elasticsearch_dsl import A
from scenario.scenario import *
from scenario.utils import *

import json
import re
import base64
import gzip
import binascii

"""

https://www.darkoperator.com/blog/2017/10/14/basics-of-tracking-wmi-activity


Microsoft-Windows-WMI-Activity/Operational
	5857 => Provider Loading: shoudl do aggregation and check for unusual path / binary
		https://github.com/jaredcatkinson/EvilNetConnectionWMIProvider
	
	WMI Error constant: https://docs.microsoft.com/fr-fr/windows/win32/wmisdk/wmi-error-constants?redirectedfrom=MSDN
		0x80041003 => access denied check on 5858 events


	Temporary Events
		When the Event Consumer is registered with Register-WmiEvent we get the following event logged on the system.
		5860 =>

	Permanent Events
		
		5861 => 
	
"""

class WMIProviderPath(ElasticScenario):
	def __init__(self):
		super(WMIProviderPath, self).__init__()

	def process(self):
		wmi_activity = ( MultiMatch(query='5857', fields=[self.get_mapping('evt_event_id_field')]) ) \
			& MultiMatch(query='Microsoft-Windows-WMI-Activity/Operational', fields=self.get_mapping('evt_channel_field_k'))

		if self.filter:
			wmi_activity &= self.filter

		self.search = self.search.query(wmi_activity)

		# self.search.aggs.bucket('computer', 'terms', field=self.get_mapping('evt_system_field_k'), size = self.bucket_size)\
		# 	.bucket('provider', 'terms', field=self.get_mapping('evt_wmi_provider_path_k'), size = self.bucket_size)


		self.search.aggs.bucket('provider', 'terms', field=self.get_mapping('evt_wmi_provider_path_k'), size = self.bucket_size)

		whitelist = self.get_conf('whitelist', default=[])

		self.alert.init(['Path', 'Nb Hits'])
		self.resp = self.search.execute()
		for wmi_data in self.resp.aggregations.provider:
			# TODO :Check if in whitelist
			matches = [path for path in whitelist if path in wmi_data.key]
			if not matches:
				self.alert.add_alert([wmi_data.key, wmi_data.doc_count])

