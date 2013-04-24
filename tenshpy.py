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

if '-d' in sys.argv:
  formatter = logging.Formatter('%(asctime)s %(name)-7s %(levelname)7s - %(message)s', datefmt='%H:%M:%S')
  handler = logging.StreamHandler()
  handler.setFormatter(formatter)
  logger = logging.getLogger('tenshpy')
  logger.setLevel(logging.DEBUG)
  logger.addHandler(handler)
else:
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

  pg = None
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

    if l == 'gorp':
      logger.debug('gorp: %s' % pg)
      pg = None
      continue

    if re.match('(%s)(,[^ ]+)? .+' % '|'.join(queues), l):
      logger.debug('l: %s' % l)
      if not pg:
        re_line.append(l)
      else:
        re_prog[pg].append(l)
      
    else:
      logger.warn('Invalid conf line: %s' % l)

  return re_prog, re_line

#logger.debug('re_prog')
#for p, r in re_prog.items():
#  print('%s: %s' % (p, r))

#logger.debug('re_line')
#for r in re_line:
#  print('%s' % r)

def report(q):
    logger.debug('reporting: %s' % q)
    if q == 'trash': return

    email = []
    for item, count in sorted(queues[q].items(), reverse=True):
      email.append('%d: %s' % (count, item))

    if email:
      logger.debug('Sending: %s' % email)
      conn = SMTP()
      conn.connect('127.0.0.1', 25)
      conn.ehlo('127.0.0.1')
      conn.mail('tenshpy')
      conn.rcpt('root')
      conn.data('Subject: tenshpy - %s\n\n%s\n' % (q, '\n'.join(email)))
      conn.quit()


def monitor():
  
  start_times = {}
  for q in delays:
    start_times[q] = time()


  while True:

    for q, t in start_times.items():
      if time() - t > delays[q]:
        report(q)
        queues[q] = {}
        start_times[q] = time()

    sleep(5)

    rlist, _, _ = select(fds, [], [])
    if not rlist: continue

    for fd in rlist:
      f = fdmap[fd]
      while True:
        l = fd.readline()
        l = l.rstrip()
        if not l: break
        logger.debug('%s: %s' % (f, l))

        m = logline_re.match(l)
        if not m:
          logger.warn('Unsupported logline: %s' % l)
          continue

        l = m.group(1)
        m = msgline_re.match(l)
        if not m:
          prog, mesg = 'NoProg', l
        else:
          prog, _, mesg = m.groups()

        item = '%s: %s' % (prog, mesg)

        if prog not in re_prog:
          relist = re_line
        else:
          relist = re_prog[prog] + re_line

        for xpr in relist:
          qname, regex = xpr.split(' ', 1)
          m = re.match(regex, mesg)

          if not m:
            logger.debug('Not matching: %s' % xpr)
            continue

          logger.debug('Matching: %s %s' % (qname, regex))

          for g in m.groups():
            mesg = mesg.replace(g, '___', 1)

          item = '%s: %s' % (prog, mesg)
          logger.debug('item: %s' % item)

          if ',' not in qname:
            qmatch = qname
            break

          qnames = qname.split(',')
          qmatch = qnames[0]

          if item not in cache:
            cache[item] = [1, time()]
            break

          cache[item][0] += 1

          count, start = cache[item]
          logger.debug('count: %d, start: %d' % (count, start))

          for n in qnames[1:]:
            qname, rate = n.split(':')
            x, y = rate.split('/')
            logger.debug('x: %s, y: %s' % (x, y))

            if count >= int(x):
              delta = time() - start
              logger.debug('delta: %d' % delta)

              if delta <= int(y):
                logger.debug('rate match')
                qmatch = qname

                total = 0
                for queue in queues.values():
                  if item in queue:
                    total += queue[item]
                    logger.debug('new total: %d' % total)
                    del queue[item]

                queues[qmatch][item] = total
                del cache[item]

          break

        logger.debug('qmatch: %s' % qmatch)
        queue = queues[qmatch]

        if item not in queue:
          queue[item] = 1
        else:
          queue[item] += 1

def open_logs(logfiles):
  fdmap = {}
  fds = []
  for f in logfiles:
    fd = open(f)
    fd.seek(0, 2)
    fds.append(fd)
    fdmap[fd] = f

  return fds, fdmap

def flush_queues(signum, sframe):
  logger.info('Flushing queues (signum: %d)' % signum)
  global cache, re_prog, re_line, fds, fdmap

  if signum == signal.SIGHUP:
    cache = {}
    re_prog, re_line = load_conf()
    fds, fdmap = open_logs(logfiles)
  else:
    for q in delays:
      report(q)
    sys.exit(0)
    
# init
signal.signal(signal.SIGINT, flush_queues)
signal.signal(signal.SIGTERM, flush_queues)
signal.signal(signal.SIGHUP, flush_queues)

logline_re = re.compile('\w{3}  ?\d{1,2} \d{2}:\d{2}:\d{2} \w+ (.+)$')
msgline_re = re.compile('([a-zA-Z0-9_/.-]+)(\[\d+\])?: (.*)$')
logfiles = [
  '/var/log/messages',
  '/var/log/secure',
  '/var/log/maillog',
  '/var/log/twitstlk.log',
  '/var/log/ulogd/ulogd.syslogemu']

delays = {
  'security': 30,     # 30"
  'unexpected': 2*60, # 2'
  'report': 30*60,    # 30'
  'mail': 8*3600,     # 8h
  'trash': 60}

queues = {} # {'security': {}, ...
for q in delays:
  queues[q] = {}

cache = {} # {'sshd: Failed password for': [count, start_time], ...}
re_prog, re_line = load_conf()
fds, fdmap = open_logs(logfiles)

while True:
  try:
    monitor()

  except KeyboardInterrupt:
    sys.exit(0)

  except Exception as e:
    logger.error('except: %s' % e)

# vim: ts=2 sw=2 sts=2 et fdm=marker
