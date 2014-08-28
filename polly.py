#!/usr/bin/env python

"""polly - build a corpus from an IMAP folder and use it to generate passwords.

usage: %(PROG)s -s server -u user -p password -f folder [ -c config ]

All command line flags are required unless they are specified in the config
file. The server is the IMAP server to use.  The user is the IMAP user,
e.g., frammitz@gmail.com. The password is the password for the given server
on the IMAP server. The folder is the name of the folder on the IMAP server
to monitor for mail.

The config file has a single section, Polly. Within that section, each of
the server, user, password, and folder options may be given. In addition, a
'common' option may be given, a floating point number between 0 and 1
(default 0.6) which defines the threshold above which a word is assumed to
be used commonly in the corpus, and can thus be used in generated
passwords. This option may only be given in the config file.

"""

from ConfigParser import RawConfigParser, NoOptionError
import cPickle as pickle
import datetime
import email
import getopt
import imaplib
import os
import random
import string
import sys
import textwrap
import threading
import time

PROG = os.path.split(sys.argv[0])[1]

class Polly(object):
    def __init__(self):
        self.punct = set(string.punctuation+string.digits)
        self.msg_ids = set()
        self.words = {}
        self.emitted = set()
        self.bad = set()
        self.latest = datetime.datetime(2014, 8, 22, 0, 0, 0)
        self.pfile = os.path.join(os.path.dirname(__file__), "polly.pkl")
        self.load_pfile()
        # Workers will acquire/release Polly to operate on internal data.
        self.sema = threading.Semaphore()

    def __enter__(self):
        self.sema.acquire()
        return self

    def __exit__(self, _type, _value, _traceback):
        self.sema.release()

    def get_password(self):
        words = list(self.emitted)
        random.shuffle(words)
        return " ".join(words[0:4])

    def bad_polly(self, word):
        self.bad.add(word)
        self.emitted.discard(word)

    def get_not_words(self, dictfile):
        with open(dictfile) as dictfp:
            dict_words = set([w.strip() for w in dictfp])
            return sorted(self.emitted - dict_words)

    def load_pfile(self):
        try:
            with open(self.pfile, "rb") as pfile:
                (self.msg_ids, self.words,
                 self.emitted, self.latest, self.bad) = pickle.load(pfile)
        except IOError:
            pass

    def save_pfile(self):
        with open(self.pfile, "wb") as pfile:
            pickle.dump((self.msg_ids, self.words,
                         self.emitted, self.latest, self.bad), pfile)

    def process_text(self, text, threshold):
        "must be called inside a 'with' statement."
        for word in text.split():
            if len(word) < 4 or set(word) & self.punct or word.lower() != word:
                continue
            self.words[word] = self.words.get(word, 0) + 1
            if (word not in self.emitted and
                self.words[word] > 10 and
                len(self.words) > 100):
                counts = sorted(self.words.values())
                if counts.index(self.words[word]) >= threshold * len(self.words):
                    self.emitted.add(word)

    def print_statistics(self):
        print "messages:", len(self.msg_ids)
        print "all words:", len(self.words)
        print "common words:", len(self.emitted)
        print "'bad' words:", len(self.bad)

def usage(msg=""):
    if msg:
        print >> sys.stderr, msg
        print >> sys.stderr
    print >> sys.stderr, __doc__ % globals()

def main(args):
    options = {
        "server": None,
        "user": None,
        "password": None,
        "folder": None,
        "common": 0.60,         # threshold for a 'common' word
        }
    configfile = None
    opts, args = getopt.getopt(args, "s:u:p:f:c:h")
    for opt, arg in opts:
        if opt == "-u":
            options["user"] = arg
        elif opt == "-p":
            options["password"] = arg
        elif opt == "-f":
            options["folder"] = arg
        elif opt == "-s":
            options["server"] = arg
        elif opt == "-c":
            configfile = arg
        elif opt == "-h":
            usage()
            return 0
        # TBD. Allow user, password, folder to be defined in an INI file.

    if configfile is not None:
        # Fill in what wasn't given on the command line.
        config = RawConfigParser()
        config.read(configfile)
        for key in options:
            if options[key] is None:
                try:
                    value = config.get("Polly", key)
                except NoOptionError:
                    pass
                else:
                    options[key] = value
        # common option is special, as it has a default value and may not be
        # given on the command line. We therefore always try to read it from
        # the config file.
        try:
            common = config.getfloat("Polly", "common")
        except NoOptionError:
            pass
        else:
            options["common"] = common

    if None in options.values():
        usage("Server, user, password and folder are all required.")
        return 1

    polly = Polly()

    procmail_t = threading.Thread(target=read_imap, name="imap-thread",
                                  args=(polly, options))

    procmail_t.daemon = True
    procmail_t.start()
    try:
        get_commands(polly)
    except KeyboardInterrupt:
        pass
    finally:
        polly.save_pfile()

    return 0

def get_commands(polly):
    try:
        last_command = None
        while True:
            sys.stdout.write("? ")
            sys.stdout.flush()
            command = sys.stdin.readline()
            if not command:
                break
            command = command.strip()
            if not command:
                # repeat last command
                if last_command is None:
                    print "No last command to repeat!"
                    continue
                command = last_command
            last_command = command
            if command == "password":
                with polly:
                    print polly.get_password()
            elif command == "stat":
                with polly:
                    polly.print_statistics()
            elif command == "exit":
                break
            elif command in ("help", "?"):
                print "commands:"
                print "  password - generate a password"
                print "  bad word word ... - mark one or more words as bad"
                print "  dict dictfile - report words not in dictfile"
                print "  stat - print some simple statistics"
                print "  <RET> - repeat last command"
                print "  help or ? - this help"
                print "  exit - exit"
            else:
                command, rest = command.split(None, 1)
                if command == "bad":
                    with polly:
                        for word in rest.split():
                            polly.bad_polly(word)
                elif command == "dict":
                    with polly:
                        not_really_words = " ".join(polly.get_not_words(rest))
                        print textwrap.fill(not_really_words)

    except KeyboardInterrupt:
        pass

def read_imap(polly, options):
    mail = imaplib.IMAP4_SSL(options["server"])
    mail.login(options["user"], options["password"])
    mail.list()
    # Out: list of "folders" aka labels in gmail.
    mail.select(options["folder"])

    while True:
        with polly:
            stamp = polly.latest.strftime("%d-%b-%Y")
        constraint = "(SENTSINCE %s)" % stamp
        result, data = mail.uid('search', None, constraint)
        if result != "OK":
            print >> sys.stderr, "Failed to search for constraint:", constraint
            return

        for uid in data[0].split():
            result, data = mail.fetch(uid, "(RFC822)")
            try:
                message = email.message_from_string(data[0][1])
            except TypeError:
                continue

            msg_id = message["Message-Id"]
            with polly:
                if msg_id in polly.msg_ids:
                    continue
                polly.msg_ids.add(msg_id)
                text = get_text(message)
                if text is None:
                    continue
                polly.process_text(text, options["common"])
                polly.latest = datetime.datetime.now()
        time.sleep(60)

def get_text(message):
    maintype = message.get_content_maintype()
    if maintype == 'multipart':
        for part in message.get_payload():
            if part.get_content_maintype() == 'text':
                return part.get_payload()
    elif maintype == 'text':
        return message.get_payload()

if __name__ == "__main__":
    main(sys.argv[1:])
