# -*- coding: utf-8 -*-

from writer.writer import Writer
from scenario.scenario import Alerts

class CSVWriter(Writer):
	"""docstring for ConsoleWriter"""
	def __init__(self, out, separator = '|', multiline = False):
		super(CSVWriter, self).__init__(out)
		self.separator = separator
		self.multiline = multiline


	def write(self, alerts):

		self.out.write(self.separator.join(alerts.header))
		self.out.write('\n')

		if not alerts.please_do_not_sort_me:
			for data in sorted(alerts.data, key=lambda x: x[0]):
				data = [str(x).rstrip() for x in data]
				if not self.multiline:
					data = [x.replace('\r', '<br>').replace('\n', '<br>') for x in data]

				self.out.write(self.separator.join(data))
				self.out.write('\n')
		else:
			for data in alerts.data:
				data = [str(x).rstrip() for x in data]
				if not self.multiline:
					data = [x.replace('\r', '<br>').replace('\n', '<br>') for x in data]

				self.out.write(self.separator.join(data))
				self.out.write('\n')
