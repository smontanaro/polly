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
import dateutil.parser

PROG = os.path.split(sys.argv[0])[1]

DFLT_DATE = datetime.datetime(2014, 8, 1, 0, 0, 0)
class Polly(object):
    def __init__(self, options):
        self.reader = None
        self.options = options
        self.punct = set(string.punctuation+string.digits)
        self.msg_ids = set()
        self.words = {}
        self.emitted = set()
        self.bad = set()
        # This keeps me from going back too far in the folder. I suppose I
        # should make this a parameter...
        self.latest = DFLT_DATE
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

    def process_text(self, text):
        "must be called inside a 'with' statement."
        threshold = self.options["common"]
        for word in text.split():
            if (word in self.bad or
                len(word) < 4 or
                set(word) & self.punct or
                word.lower() != word):
                continue
            self.words[word] = self.words.get(word, 0) + 1
            if (word not in self.emitted and
                self.words[word] > 10 and
                len(self.words) > 100):
                counts = sorted(self.words.values())
                min_index = threshold * len(self.words)
                if counts.index(self.words[word]) >= min_index:
                    self.emitted.add(word)

    def print_statistics(self):
        print "message ids:", len(self.msg_ids)
        print "all words:", len(self.words)
        print "common words:", len(self.emitted)
        print "'bad' words:", len(self.bad)
        print "last date:", self.latest

    def start_reader(self):
        if self.reader is None or not self.reader.is_alive():
            note("starting IMAP thread.")
            self.reader = threading.Thread(target=read_imap,
                                            name="imap-thread",
                                            args=(self,))
            self.reader.daemon = True
            self.reader.start()

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

    polly = Polly(options)

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
            elif command == "read":
                with polly:
                    polly.start_reader()
            elif command == "stat":
                with polly:
                    polly.print_statistics()
            elif command == "save":
                with polly:
                    polly.save_pfile()
            elif command == "exit":
                break
            elif command in ("help", "?"):
                print "commands:"
                print "  password - generate a password"
                print "  bad word word ... - mark one or more words as bad"
                print "  dict dictfile - report words not in dictfile"
                print "  read - restart the read_imap thread if it stopped"
                print "  stat - print some simple statistics"
                print "  save - write the pickle save file"
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

def note(msg):
    sys.stdout.write("\n%s\n? " % msg)
    sys.stdout.flush()

def read_imap(polly):
    while True:
        read_loop(polly)
        time.sleep(600)

def read_loop(polly):
    with polly:
        latest = polly.latest
        options = polly.options.copy()
        msg_ids = polly.msg_ids.copy()

    with IMAP(options["server"]) as mail:
        mail.login(options["user"], options["password"])
        mail.select(options["folder"])

        nhdrs = nmsgs = nnew = 0
        stamp = latest.strftime("%d-%b-%Y")
        constraint = "(SENTSINCE %s)" % stamp
        try:
            _result, data = mail.uid('search', None, constraint)
        except imaplib.IMAP4.error:
            print >> sys.stderr, "Failed to search for constraint:", constraint
            print >> sys.stderr, "Please send 'read' command later"
            return

        uids = data[0].split()
        if uids:
            note("Will process %d uids" % len(uids))
        for uid in uids:
            # First, check the message-id to see if we've already seen it.
            _, data = mail.fetch(uid, "(BODY[HEADER.FIELDS (MESSAGE-ID)])")
            nhdrs += 1
            try:
                message = email.message_from_string(data[0][1])
            except TypeError:
                continue
            msg_id = message.get("Message-ID")
            if msg_id is None or msg_id in msg_ids:
                continue
            msg_ids.add(msg_id)

            # Okay, we haven't seen this message yet. Process its text
            # (well, the first text part we come across).
            nmsgs += 1
            _, data = mail.fetch(uid, "(RFC822 BODY.PEEK[])")
            try:
                message = email.message_from_string(data[0][1])
            except TypeError:
                continue
            text = get_text(message)
            if text is None:
                continue

            nnew += 1
            with polly:
                polly.process_text(text)

            if nnew % 100 == 0:
                note("hdrs: %d msgs: %d new: %d" % (nhdrs, nmsgs, nnew))
                with polly:
                    polly.latest = latest
                    polly.msg_ids = msg_ids
            # Remember the date for the next time.
            msg_date = message.get("Date")
            if msg_date is None:
                msg_date = DFLT_DATE
            else:
                try:
                    msg_date = dateutil.parser.parse(msg_date)
                    msg_date = msg_date.replace(tzinfo=None)
                except TypeError:
                    note("Invalid date string: %r" % msg_date)
                    msg_date = DFLT_DATE
            latest = max(latest, msg_date)

            with polly:
                polly.latest = latest

            note("hdrs: %d msgs: %d new: %d" % (nhdrs, nmsgs, nnew))

class IMAP(imaplib.IMAP4_SSL):
    def __init__(self, server):
        imaplib.IMAP4_SSL.__init__(self, server)

    def __enter__(self):
        return self

    def __exit__(self, _type, _value, _traceback):
        self.close()

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
