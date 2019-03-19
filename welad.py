#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    TODO: description
"""
__progname__ = "Welad"
__author__ = "Bastien Lardy"
__version__ = "0.1"

import argparse
import logging
import sys

from scenario.logon import LogonHistory, RDPHistory, FailedLogonHistory, LogonStat
from scenario.services import MaliciousPowerShell, BITSService
from scenario.processes import ProcessTree, ProcessStat
from scenario.search import Search

from writer.console import ConsoleWriter
from writer.csv import CSVWriter


LOG_FORMAT = '[%(asctime)s][{}][{}][%(levelname)s]%(funcName)s:'.format(__progname__, __version__) + ' %(message)s'
LOG_VERBOSITY = {
	'DEBUG' : logging.DEBUG,
	'INFO' : logging.INFO,
	'WARNING' : logging.WARNING,
	'ERROR' : logging.ERROR,
	'CRITICAL' : logging.CRITICAL,
}


def init_parser(scenarios, writers):
	""" It instantiate an Argument parser
	     And then sub-parsers for each scenario

	    It returns the parser
	"""
	parser = argparse.ArgumentParser()
	parser.add_argument('--tag', help="tag")
	parser.add_argument("-v", "--verbosity", help="increase output verbosity", choices = LOG_VERBOSITY, default='WARNING')
	parser.add_argument("-o", "--output", type=argparse.FileType('w'), help="output file", default=sys.stdout)
	parser.add_argument("-w", "--writer", choices = writers, default=writers[0], help="writer to use")
	
	subparsers = parser.add_subparsers(help='Scenarios',  dest='scenar')
	for scenar in scenarios:
		p = subparsers.add_parser(scenar.__class__.__name__, help=scenar.help)
		scenar.add_argument(p)

	return parser


def main():
	# Instantiate all scenarios
	#   TODO: maybe I should do something with __init__.py to load those....	
	SCENARS = [LogonHistory(), RDPHistory(), MaliciousPowerShell(), BITSService(), FailedLogonHistory(), Search(), ProcessTree(), ProcessStat(), LogonStat()]
	SCENARS_DICT = {}
	for scenar in SCENARS:
		SCENARS_DICT[scenar.__class__.__name__] = scenar

	WRITERS = {
		'console' : ConsoleWriter,
		'csv' : CSVWriter,
		
	}

	# get arguments
	args = init_parser(SCENARS, [k for k in WRITERS.keys()]).parse_args()

	# configure logging
	logging.basicConfig(format=LOG_FORMAT, level=LOG_VERBOSITY[args.verbosity], datefmt='%Y-%m-%d %I:%M:%S')
	logging.warning('Hello hello....')

	if SCENARS_DICT.get(args.scenar, False):
		SCENARS_DICT[args.scenar].init(args)
		SCENARS_DICT[args.scenar].process()

		WRITERS[args.writer](args.output).write(SCENARS_DICT[args.scenar].alert)
	else:
		logging.error('Please specify something... Use -h !!!')

	logging.warning('Bye bye....')





if __name__ == '__main__':
	main()