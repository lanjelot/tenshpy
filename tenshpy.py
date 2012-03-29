#!/usr/bin/env python

from select import select
from time import sleep, time
from threading import Thread, active_count
from Queue import Queue, Empty, Full
from smtplib import SMTP
import signal
import re
import sys

import logging
from logging.handlers import SysLogHandler
formatter = logging.Formatter('%(name)s[%(process)d]: %(levelname)s - %(message)s')
handler = SysLogHandler(address="/dev/log")
handler.setFormatter(formatter)
logger = logging.getLogger('tenshpy')
logger.setLevel(logging.INFO)
logger.addHandler(handler)

def load_conf(conf='/etc/tenshpy.conf'):
  re_prog = {}
  re_line = []

  logger.info('Loading conf: %s' % conf)

  pg = ''
  for l in open(conf):
    l = l.strip()
    if not l: continue
    if l[0] == '#': continue

    if l.startswith('prog'):
      pg = l[5:]
      logger.debug('prog: %s' % pg)
      if pg not in re_prog:
        re_prog[pg] = []
      continue

    if l.startswith('gorp'):
      logger.debug('gorp: %s' % pg)
      pg = ''
      continue

    if re.match('(%s) .+' % '|'.join(queues.keys()), l):
      logger.debug('l: %s' % l)
      action, regex = l.split(' ', 1)
      if not pg:
        re_line.append(l)
      else:
        re_prog[pg].append(l)
      
    else:
      logger.warn('Invalid line: %s' % l)

  return re_prog, re_line

#logger.debug('re_prog')
#for p, r in re_prog.iteritems():
#  print('%s: %s' % (p, r))

#logger.debug('re_line')
#for r in re_line:
#  print('%s' % r)

def report(p):
    logger.debug('report: %s' % p)

    if p != 'trash':

      email = []
      for item, count in sorted(queues[p].iteritems(), reverse=True):
        email.append('%d: %s' % (count, item))

      if email:
        logger.debug('Sending: %s' % email)
        conn = SMTP()
        conn.connect('127.0.0.1', 25)
        conn.ehlo('logmon')
        conn.mail('logmon')
        conn.rcpt('root')
        conn.data('Subject: logmon - %s\n\n%s\n' % (p, '\n'.join(email)))
        conn.quit()

    queues[p] = {}

def monitor():
  
  stimes = {}
  for p in delays.iterkeys():
    stimes[p] = time()

  while True:

    for p, t in stimes.iteritems():
      if time() - t > delays[p]:
        report(p)
        stimes[p] = time()

    sleep(3)
    
    rlist, _, _ = select(fds, [], [])
    if not rlist: continue

    for fd in rlist:
      f = fdmap[fd]
      s = fd.readline().rstrip()
      if not s: continue
      logger.debug('%s: %s' % (f, s))

      m = logre.match(s)
      if not m:
        logger.warn('unsupported logline: %s' % s)
        continue 

      prog, _, mesg = m.groups()
      item = '%s: %s' % (prog, mesg)

      if prog not in re_prog:
        relist = re_line[:] 
      else:
        relist = re_prog[prog]

      target = queues['unexpected']

      for xpr in relist:
        action, regex = xpr.split(' ', 1)
        m = re.match(regex, mesg)

        if not m:
          logger.debug('Not matching: %s' % xpr)
          continue
        
        logger.debug('Matching: %s' % action)

        for g in m.groups():
          mesg = re.sub(g, '___', mesg, count=1)

        item = '%s: %s' % (prog, mesg)
        target = queues[action]
        break 

      logger.debug('item: %s' % item)
      if item not in target:
        target[item] = 1
      else:
        target[item] += 1

def flush_queues(signum, sframe):
  logger.info('Flushing queues (signum: %d)' % signum)

  for p in delays.iterkeys():
    report(p)

  if signum == signal.SIGHUP:
    re_prog, re_line = load_conf()

  else:
    sys.exit(0)
    
# init
signal.signal(signal.SIGINT, flush_queues)
signal.signal(signal.SIGTERM, flush_queues)
signal.signal(signal.SIGHUP, flush_queues)

logre = re.compile('\w{3}  ?\d{1,2} \d{2}:\d{2}:\d{2} dora ([a-zA-Z0-9_/-]+)(\[\d+\])?: (.*)$')
logfiles = ['/var/log/messages', '/var/log/secure', '/var/log/maillog', '/var/log/twitstlk.log']
fdmap = {}
fds = []

delays = {'security': 5, 'unexpected': 2*60, 'report': 30*60, 'trash': 60}
queues = {}
for p in delays.keys():
  queues[p] = {}

re_prog, re_line = load_conf()

for f in logfiles:
  fd = open(f)
  fd.seek(0, 2)
  fds.append(fd)
  fdmap[fd] = f

while True:
  try:
    monitor()

  except KeyboardInterrupt:
    sys.exit(0)

  except Exception as e:
    logger.error('except: %s' % e)

# vim: ts=2 sw=2 sts=2 et fdm=marker
