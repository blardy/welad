# -*- coding: utf-8 -*-

from writer.writer import Writer
from scenario.scenario import Alerts

class ConsoleWriter(Writer):
	"""docstring for ConsoleWriter"""
	def __init__(self, out):
		super(ConsoleWriter, self).__init__(out)


	def write(self, alerts, max_size=0):
		# Oui ca donne envie de vomir, et alors ?
		format_str = ''
		for size in alerts.sizes:
			if max_size and size > max_size:
				size = max_size
			format_str += '|{: ^' + str(size + 2) + '}'
		format_str += '|\n'

		data_str = format_str.replace('^', '<')

		self.out.write(format_str.replace('|', '_').replace(' ', '_').format( *[ '' for x in alerts.header] ))
		self.out.write(format_str.format( *alerts.header ))
		self.out.write(format_str.replace('|', '_').replace(' ', '_').format( *[ '' for x in alerts.header] ))

		for data in alerts.data:
			# Q&D we want all data ahving the same number of newline for printing purposes
			data = [str(x).rstrip() for x in data]
			max_newline = 0
			for value in data:
				max_newline = max( len(value.split('\n')), max_newline)
			data = [ str(x) + '\n' * (max_newline-len(x.split('\n'))) for x in data]

			sub_line = []
			for i in range(0, max_newline + 1):
				sub_line.append([])

			for field_data in data:
				for line_idx, line in enumerate(field_data.split('\n')):
					line = line
					sub_line[line_idx].append(line)

			for line in sub_line:
				if line:
					self.out.write(data_str.format( *line ))

		self.out.write(format_str.replace('|', '_').replace(' ', '_').format( *[ '' for x in alerts.header] ))
