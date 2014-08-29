#!/usr/bin/python2.6

from optparse import OptionParser
import socket
import threading
import datetime
import struct
import time
import math
import re

def banner():
	print '                                    _._                                          '
        print '                               _.-="_-         _                                 '
        print '                          _.-="   _-          | ||"""""""---._______     __..    '
        print '              ___.===""""-.______-,,,,,,,,,,,,`-\'\'----" """""       """""  __\'   '
        print '       __.--""     __        ,\'                   o \           __        [__|   '
        print '  __-""=======.--""  ""--.=================================.--""  ""--.=======:  '
        print ' ]       [w] : /        \ : |========================|    : /        \ :  [w] :  '
        print ' V___________:|          |: |========================|    :|          |:   _-"   '
        print '  V__________: \        / :_|=======================/_____: \        / :__-"     '
        print '  -----------\'  ""____""  `-------------------------------\'  ""____""            '


# NTP-Proxy Class
class NTProxy( threading.Thread ):
	# Stop Flag
	stopF = False
	# Temporal control
	seen = {}
	# Constructor
	def __init__( self, socket ):
		threading.Thread.__init__( self )
		self.step = 0
		self.ntp_delta = ( datetime.date(*time.gmtime(0)[0:3]) - datetime.date(1900, 1, 1) ).days * 24 * 3600
		self.stopF = False
		self.socket = socket
		self.socket.settimeout(5.0)	# Needed: If not socket.recvfrom() waits forever

	# Set the step to the future
	def select_step( self ):
		# Get current date
		current_time = time.time()
		current_week_day = time.gmtime( current_time )[6]
		current_month_day = time.gmtime( current_time )[2]
		# Look for the same week and month day, minimum a thousand days in the future
		week_day = 10000
		month_day = 10000
		future_time = current_time + (3 * 12 * 4 * 7 * 24 * 3600)
		while not ((week_day == current_week_day) and (month_day == current_month_day)):
			future_time = future_time + (7 * 24 * 3600)
			week_day = time.gmtime( future_time )[6]
			month_day = time.gmtime( future_time )[2]
		self.step = future_time - current_time

	# Select a new time in the future
	def newtime( self ):
		current_time = time.time()
		future_time = (current_time + self.step) + self.ntp_delta
		return future_time

	# Stop Method
	def stop( self ):
		self.stopF = True

	# Run Method
	def run( self ):
		self.select_step()
		while not self.stopF:
			# When timeout we need to catch the exception
			try:
				data,source = self.socket.recvfrom(1024)
				info = self.extract( data )
				timestamp = self.newtime()
				fingerprint,data = self.response( info, timestamp )
				socket.sendto( data, source )
				# Only print if it's the first packet
				epoch_now = time.time()
				if ( not source[0] in self.seen ) or ( (source[0] in self.seen) and (epoch_now - self.seen[source[0]]) > 30 ):
					self.seen[source[0]] = epoch_now
					# Year-Month-Day Hour:Mins
					aux = time.gmtime(timestamp-self.ntp_delta)
					future_time = str(aux[0])+'-'+str(aux[1])+'-'+str(aux[2])+' '+str(aux[3])+':'+str(aux[4])
					aux = time.gmtime(time.time())
					current_time = str(aux[3])+':'+str(aux[4])+':'+str(aux[5])
					print fingerprint + ' detected!'
					print "[%s] Sended to %s:%d - Going to the future! %s" % (current_time,source[0],source[1],future_time)
			except:
				continue

	# Extract query information
	def extract( self, data ):
		# Format from https://github.com/limifly/ntpserver/
		unpacked = struct.unpack( '!B B B b 11I', data[0:struct.calcsize('!B B B b 11I')] )
		# Extract information
		info = {}
		info['leap']			= unpacked[0] >> 6 & 0x3
		info['version']			= unpacked[0] >> 3 & 0x7
		info['mode']			= unpacked[0] & 0x7
		info['stratum']			= unpacked[1]
		info['poll']			= unpacked[2]
		info['precision']		= unpacked[3]
		info['root_delay']		= float(unpacked[4])/2**16
		info['root_dispersion']		= float(unpacked[5])/2**16
		info['ref_id']			= unpacked[6]
		info['ref_timestamp']		= unpacked[7] + float(unpacked[8])/2**32
		info['orig_timestamp']		= unpacked[9] + float(unpacked[10])/2**32
		info['orig_timestamp_high']	= unpacked[9]
		info['orig_timestamp_low']	= unpacked[10]
		info['recv_timestamp']		= unpacked[11] + float(unpacked[12])/2**32
		info['tx_timestamp']		= unpacked[13] + float(unpacked[14])/2**32
		info['tx_timestamp_high']	= unpacked[13]
		info['tx_timestamp_low']	= unpacked[14]
		# Return useful info for respose
		return info		

	# Create response packet
	def response( self, info, timestamp ):
		if ( info['leap'] == 0 and info['version'] == 4 and (info['mode'] ==3 or info['mode'] == 4) ):
			return self.response_osx( info, timestamp )
		if ( (info['leap'] == 3 or info['leap'] == 192) and info['version'] == 4 and info['mode'] == 3 ):
			return self.response_linux( info, timestamp )
		if info['version'] == 3:
			return self.response_win( info, timestamp )
		return self.response_default( info, timestamp )

	def generate_param( self, info, timestamp ):
		# Format from https://github.com/limifly/ntpserver/
		# Define response params
		param = {}
		param['ID'] = 'Unknown'
		param['leap'] = 0			# No warnings, no errors
		param['version'] = info['version']	# Use the same request version
		param['mode'] = 4			# Always answer server mode
		param['stratum'] = 2			# Highest NTP priority
		param['poll'] = 9			# As less poll time as possible
		param['precision'] = -20		# Maximum precision
		param['root_delay'] = 0
		param['root_dispersion'] = 0
		param['ref_id'] = info['ref_id']
		param['ref_timestamp'] = timestamp - 5
		param['orig_timestamp'] = 0
		param['orig_timestamp_high'] = info['tx_timestamp_high']
		param['orig_timestamp_low'] = info['tx_timestamp_low']
		param['recv_timestamp'] = timestamp
		param['tx_timestamp'] = timestamp
		param['tx_timestamp_high'] = 0
		param['tx_timestamp_low'] = 0
		return param

	def response_linux( self, info, timestamp ):
		param = self.generate_param( info, timestamp )
		param['ID'] = 'Linux'
		#param['leap'] = 4
		#param['version'] = info['version']
		#param['mode'] = 4
		# Construct packet
		return param['ID'],self.packetize( info, param )

	def response_osx( self, info, timestamp ):
		param = self.generate_param( info, timestamp )
		param['ID'] = 'Mac OS X'
		#param['ref_id'] = 0 # 17.72.133.55
		#param['leap'] = 0
		#param['version'] = 4
		#param['mode'] = 4
		#param['poll'] = 9
		# Construct packet
		return param['ID'],self.packetize( info, param )

	def response_win( self, info, timestamp ):
		param = self.generate_param( info, timestamp )
		param['ID'] = 'Windows'
		#param['version'] = 3
		# Construct packet
		return param['ID'],self.packetize( info, param )

	def response_default( self, info, timestamp ):
		param = self.generate_param( info, timestamp )
		# Construct packet
		return param['ID'],self.packetize( info, param )
	
	def packetize( self, info, param ):
		# Format from https://github.com/limifly/ntpserver/
		#print param['ID'] + ' detected!'
		# Construct packet
		packed = struct.pack('!B B B b 11I',
		(param['leap'] << 6 | param['version'] << 3 | param['mode']),
		param['stratum'],
		param['poll'],
		param['precision'],
		int(param['root_delay']) << 16 | int(abs(param['root_delay'] - int(param['root_delay'])) * 2**16),
		int(param['root_dispersion']) << 16 |
		int(abs(param['root_dispersion'] - int(param['root_dispersion'])) * 2**16),
		param['ref_id'],
		int(param['ref_timestamp']),
		int(abs(param['ref_timestamp'] - int(param['ref_timestamp'])) * 2**32),
		param['orig_timestamp_high'],
		param['orig_timestamp_low'],
		int(param['recv_timestamp']),
		int(abs(param['recv_timestamp'] - int(param['recv_timestamp'])) * 2**32),
		int(param['tx_timestamp']),
		int(abs(param['tx_timestamp'] - int(param['tx_timestamp'] )) * 2**32) )
		# Return packet
		# int(abs(timestamp - int(timestamp)) * 2**32)
		return packed

# Usage and options
usage = "usage: %prog [options]"
parser = OptionParser(usage=usage)
parser.add_option("-i", "--interface", type="string", dest="interface", default="0.0.0.0", help="Listening interface")
parser.add_option("-p", "--port", type="int", dest="port", default="123", help="Listening port")
parser.add_option("-n", "--nobanner", action="store_false", dest="banner", default=True, help="Not show Delorean banner")
(options, args) = parser.parse_args()
ifre = re.compile('[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
if not options.interface or not ifre.match(options.interface) or options.port < 0 or options.port > 65535:
        parser.print_help()
        exit()

# Bind Socket and Start Thread
socket = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
socket.bind( (options.interface, options.port) )
NTP_Thread = NTProxy(socket)
NTP_Thread.start()

# Lets go to the future
if options.banner:
	banner()

# Wait until Keyboard Interrupt
try:
	while True:
		time.sleep(1)
except KeyboardInterrupt:
	print "Kill signal sent..."
	NTP_Thread.stop()
	NTP_Thread.join()
	socket.close()
	print "Exited"

