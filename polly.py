#!/usr/bin/env python

"""polly - build a corpus from an IMAP folder and use it to generate passwords.

usage: %(PROG)s -s server -u user -p password -f folder [ -c config ]

All command line flags are required unless they are specified in the config
file. The server is the IMAP server to use.  The user is the IMAP user,
e.g., frammitz@gmail.com. The password is the password for the given server
on the IMAP server. The folder is the name of the folder on the IMAP server
to monitor for mail.

The config file has a single section, Polly. Within that section, each of
the server, user, password, and folder options may be given. Two parameters
dictate how many words will be considered to be 'common. A 'threshold'
option may be given, a floating point number between 0 and 1 (default 0.6)
which defines the threshold above which a word is assumed to be used
commonly in the corpus, and can thus be used in generated passwords. This
option may only be given in the config file. An 'nwords' option may also be
given, which indicates the number of most common words to use when
generating passwords. The parameter which yields the smaller number of words
takes precedence.

"""

from ConfigParser import RawConfigParser, NoOptionError
import cPickle as pickle
import datetime
import email
import getopt
import imaplib
import math
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
        self.pfile = os.path.join(os.path.dirname(__file__), "polly.pkl")
        self.bfile = os.path.join(os.path.dirname(__file__), "polly.bad")
        self.load_pfile()
        # Workers will acquire/release Polly to operate on internal data.
        self.sema = threading.Semaphore()

    def __enter__(self):
        self.sema.acquire()
        return self

    def __exit__(self, _type, _value, _traceback):
        self.sema.release()

    def get_password(self):
        nwords = self.options["nwords"]
        words = list(self.emitted)
        if len(words) > nwords and len(self.words) > nwords:
            counts = sorted(zip(self.words.values(), self.words.keys()))
            words = [w for (_count, w) in counts[:nwords]]
        random.shuffle(words)
        return " ".join(words[0:4])

    def bad_polly(self, word):
        self.bad.add(word)
        self.emitted.discard(word)

    def get_not_words(self, dictfile):
        if not os.path.exists(dictfile):
            note("%r does not exist" % dictfile)
            return []
        with open(dictfile) as dictfp:
            raw = [w.strip().lower() for w in dictfp]
            dict_words = set(raw)
            for suffix in ("ing", "ed", "es", "s", "ies"):
                dict_words |= set([w+suffix for w in raw])
            return sorted(self.emitted - dict_words)

    def add_words(self, dictfile, nwords):
        if not os.path.exists(dictfile):
            note("%r does not exist" % dictfile)
            return
        upper_and_punct = self.punct | set(string.uppercase)
        with open(dictfile) as dictfp:
            raw = [w.strip()
                     for w in dictfp
                       if (not set(w) & upper_and_punct) and len(w) > 4]
            random.shuffle(raw)
            candidates = set(raw[:nwords])
            if not self.emitted:
                # Cheat. Just initialize from the candidates.
                self.emitted |= candidates
                for word in candidates:
                    self.words[word] = 10
            else:
                while candidates & self.emitted != candidates:
                    # Keep trying until all words have been added to the
                    # good set.
                    self.consider_words(candidates)

    def rebuild(self):
        "Rebuild self.emitted from self.words."
        counts = sorted([(self.words[w], w)
                             for w in self.words if w not in self.bad])
        nwords = self.options["nwords"]
        threshold = int(len(counts) * (1 - self.options["threshold"]))
        index = min(threshold, nwords)
        words = [w for (_count, w) in counts[-index:]]
        self.emitted = set(words)

    def load_pfile(self):
        if os.path.exists(self.pfile):
            try:
                with open(self.pfile, "rb") as pfile:
                    (self.msg_ids, self.words,
                     self.emitted, self.bad) = pickle.load(pfile)
            except ValueError:
                # Bad word list is in separate plain text file.
                with open(self.pfile, "rb") as pfile:
                    (self.msg_ids, self.words,
                     self.emitted) = pickle.load(pfile)

        if os.path.exists(self.bfile):
            with open(self.bfile) as bfile:
                self.bad = set([w.strip() for w in bfile])

    def save_pfile(self):
        with open(self.pfile, "wb") as pfile:
            pickle.dump((self.msg_ids, self.words,
                         self.emitted), pfile)
        # Save bad words in a plain text file so we can retain them if
        # we decide to toss the pickle file, and so we can easily edit
        # the bad words list.
        with open(self.bfile, "w") as bfile:
            for word in sorted(self.bad):
                bfile.write(word+"\n")

    def process_text(self, text):
        "must be called inside a 'with' statement."
        self.consider_words(text.split())

    def consider_words(self, candidates):
        threshold = self.options["threshold"]
        for word in candidates:
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
        print "common words:", len(self.emitted),
        bits = math.log(len(self.emitted), 2) if self.emitted else 0
        print "entropy:", "%.2f" % bits, "bits"
        print "'bad' words:", len(self.bad)

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
        "threshold": None,
        "nwords": None,
        "verbose": None,
        }
    getters = {
        "server": "get",
        "user": "get",
        "password": "get",
        "folder": "get",
        "threshold": "getfloat",
        "nwords": "getint",
        "verbose": "getboolean",
        }

    configfile = None
    opts, args = getopt.getopt(args, "s:u:p:f:c:hv")
    for opt, arg in opts:
        if opt == "-u":
            options["user"] = arg
        elif opt == "-p":
            options["password"] = arg
        elif opt == "-f":
            options["folder"] = arg
        elif opt == "-s":
            options["server"] = arg
        elif opt == "-v":
            options["verbose"] = True
        elif opt == "-c":
            configfile = arg
        elif opt == "-h":
            usage()
            return 0

    if configfile is not None:
        # Fill in what wasn't given on the command line.
        config = RawConfigParser()
        config.read(configfile)
        for key in options:
            if options[key] is None:
                try:
                    value = getattr(config, getters[key])("Polly", key)
                except NoOptionError:
                    pass
                else:
                    options[key] = value

        # These can legitimately be unspecified.
        if options["verbose"] is None:
            options["verbose"] = False

        if options["threshold"] is None:
            options["threshold"] = 0.6

        if options["nwords"] is None:
            options["nwords"] = 2048

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
            try:
                command, rest = command.split(None, 1)
            except ValueError:
                rest = ""
            if command == "password":
                count = int(rest) if rest else 1
                if count > 20:
                    note("Try printing no more than 20 passwords at once.")
                    count = 20
                with polly:
                    nwords = polly.options["nwords"]
                    if (len(polly.emitted) > nwords and
                        len(polly.words) > nwords and
                        polly.options["verbose"]):
                        note("Using %d most common words." % nwords)
                    for _ in range(count):
                        print polly.get_password()
            elif command == "read":
                with polly:
                    polly.start_reader()
            elif command == "stat":
                with polly:
                    polly.print_statistics()
            elif command == "rebuild":
                with polly:
                    polly.rebuild()
            elif command == "save":
                with polly:
                    polly.save_pfile()
            elif command == "verbose":
                with polly:
                    polly.options["verbose"] = not polly.options["verbose"]
                    print "verbose:", polly.options["verbose"]
            elif command == "exit":
                break
            elif command in ("help", "?"):
                print "commands:"
                print "  add dictfile n - add n random words from dictfile"
                print "  bad word word ... - mark one or more words as bad"
                print "  dict dictfile - report words not in dictfile"
                print "  password [n] - generate one or more passwords"
                print "  read - restart the read_imap thread if it stopped"
                print "  rebuild - rebuild the good words from all seen"
                print "  save - write the pickle save file"
                print "  stat - print some simple statistics"
                print "  verbose - toggle verbose flag"
                print "  <RET> - repeat last command"
                print "  help or ? - this help"
                print "  exit - exit"
            else:
                if command == "bad":
                    with polly:
                        for word in rest.split():
                            polly.bad_polly(word)
                elif command == "dict":
                    with polly:
                        not_really_words = " ".join(polly.get_not_words(rest))
                        print textwrap.fill(not_really_words)
                elif command == "add":
                    with polly:
                        dictfile, nwords = rest.split()
                        nwords = int(nwords)
                        polly.add_words(dictfile, nwords)
                else:
                    note("Unrecognized command %r" % command)
    except KeyboardInterrupt:
        pass

    note("Awk! Goodbye...")

def note(msg):
    sys.stdout.write("\n%s\n? " % msg)
    sys.stdout.flush()

def read_imap(polly):
    while True:
        read_loop(polly)
        time.sleep(600)

def read_loop(polly):
    with polly:
        options = polly.options.copy()
        msg_ids = polly.msg_ids.copy()

    # Reference the verbose parameter through the options dict so the
    # user can toggle the setting on-the-fly.
    with IMAP(options["server"]) as mail:
        try:
            mail.login(options["user"], options["password"])
        except IMAP.error:
            note("login failed. check your credentials.")
            return
        if options["verbose"]:
            note("login successful.")
        (result, data) = mail.select(options["folder"])
        if result != "OK":
            note("failed to select folder %r." % options["folder"])
            return
        if options["verbose"]:
            note("select folder %r." % options["folder"])

        nhdrs = nmsgs = nnew = 0
        start = datetime.datetime.now()-datetime.timedelta(days=10)
        stamp = start.strftime("%d-%b-%Y")
        constraint = "(SENTSINCE %s)" % stamp
        try:
            result, data = mail.uid('search', None, constraint)
        except IMAP.error:
            note("failed to search for constraint: %s" % constraint)
            return
        else:
            if result != "OK":
                note("failed to search for constraint: %s" % constraint)
                return

        uids = data[0].split()
        if options["verbose"]:
            note("search successful - %d uids returned." % len(uids))
        if uids:
            note("Will process %d uids" % len(uids))
        for uid in uids:
            # First, check the message-id to see if we've already seen it.
            result, data = mail.fetch(uid, "(BODY[HEADER.FIELDS (MESSAGE-ID)])")
            if result != "OK":
                note("failed to fetch headers.")
                return

            nhdrs += 1
            try:
                message = email.message_from_string(data[0][1])
            except TypeError:
                continue
            msg_id = message.get("Message-ID")
            if msg_id is None or msg_id in msg_ids:
                continue
            msg_ids.add(msg_id)
            # Reference the verbose parameter here through
            # self.options so the user can toggle the setting
            # on-the-fly.
            with polly:
                if polly.options["verbose"]:
                    note("New message id: %s" % msg_id)

            # Okay, we haven't seen this message yet. Process its text
            # (well, the first text part we come across).
            nmsgs += 1
            result, data = mail.fetch(uid, "(RFC822 BODY.PEEK[])")
            if result != "OK":
                note("failed to fetch body.")
                return
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

            if nnew % 10 == 0:
                note("hdrs: %d msgs: %d new: %d" % (nhdrs, nmsgs, nnew))
                with polly:
                    polly.msg_ids = msg_ids.copy()
            # Remember the date for the next time.
            msg_date = message.get("Date")
            if msg_date is None:
                msg_date = DFLT_DATE
            else:
                try:
                    msg_date = dateutil.parser.parse(msg_date)
                    msg_date = msg_date.replace(tzinfo=None)
                except (ValueError, TypeError):
                    note("Invalid date string: %r" % msg_date)
                    msg_date = DFLT_DATE

        note("hdrs: %d msgs: %d new: %d" % (nhdrs, nmsgs, nnew))

class IMAP(imaplib.IMAP4_SSL):
    def __init__(self, server):
        imaplib.IMAP4_SSL.__init__(self, server)

    def __enter__(self):
        return self

    def __exit__(self, _type, _value, _traceback):
        self.logout()

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
