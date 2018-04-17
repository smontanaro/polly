#!/usr/bin/env python

"""polly - build a corpus from an IMAP folder and use it to generate passwords.

usage: %(PROG)s -s server -u user -p password -f folder [ -g N [ -H what ] ] \
        [ -G | --gui ] [ -c config ]

The server, user, password and folder flags are required unless they
are specified in the config file.  If the -g flag is given, polly will
print N passwords, then exit without starting a command loop. If the
-c flag is given, options are read from the named config file. The -s,
-u, -p, and -f flags take precedence over the values defined in the
config file.

When run with the -G or --gui flag, a graphical user interface is started.

When generating passwords, you can specify that they are to be hashed
using the -H flag. You must also give the type of hash to use. Any
hash type in Python's hashlib.algorithm tuple is acceptable.

The config file has a single section, Polly. Within that section, any of the
following options may be defined.

Options
-------

server         - the hostname of the IMAP server (required)
user           - the login name on the IMAP server (required)
password       - the password for the IMAP server (required)
folder         - the folder to check for messages (required)
nwords         - n common words to use when considering candidates
                 (default 2048)
verbose        - when True, emit more messages (default False)
punctuation    - when True, allow punctuation between words (default False)
digits         - when True, allow digits between words (default False)
minchars       - length of shortest word to use when generating passwords
                 (default 3)
maxchars       - length of longest word to use when generating passwords
                 (default 999)
edit-mode      - editor mode for readline (default 'emacs')
length         - number of words used to construct passwords (default 4)
hash           - emit passwords using $dummy$hex instead of plain text
                 passwords (for strength testing using JohnTheRipper)

Commands
--------

add dictfile n - add n random words from dictfile
bad word ...   - mark one or more words as bad
dict dictfile  - report words not present in dictfile
exit           - quit the program
help or ?      - print this help
password [n]   - generate n passwords (default 1)
read           - read messages from the IMAP server in a second thread
rebuild        - rebuild the 'good' words list
save           - write the pickle save file and bad words file
stat           - print some simple statistics about the collected words
verbose        - toggle verbose flag

Readline support is enabled, with input history saved in ~/.polly.rc.
"""

from configparser import RawConfigParser, NoOptionError
from email.iterators import typed_subpart_iterator
import pickle as pickle
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
import readline
import atexit
import binascii
import subprocess
import tkinter as tkinter

import dateutil.parser

PROG = os.path.split(sys.argv[0])[1]

DFLT_DATE = datetime.datetime(2014, 8, 1, 0, 0, 0)
class Polly(object):
    def __init__(self, options):
        self.reader = None
        self.options = options
        self.punct = set(string.punctuation)
        self.digits = set(string.digits)
        self.msg_ids = set()
        self.words = {}
        self.emitted = set()
        self.bad = set()
        self.uids = set()
        self.pfile = os.path.join(os.path.dirname(__file__), "polly.pkl")
        self.bfile = os.path.join(os.path.dirname(__file__), "polly.bad")
        self.load_pfile()
        # Workers will acquire/release Polly to operate on internal data.
        self.sema = threading.Semaphore()
        # Words already used in a password on this run.
        self.used = set()
        # Cryptographically secure random number generator.
        if self.options["unittests"]:
            # generate predictable set of "random" values for testing.
            self.cr = random._inst
            self.cr.seed(100)
        else:
            self.cr = random.SystemRandom()

    def __enter__(self):
        self.sema.acquire()
        return self

    def __exit__(self, _type, _value, _traceback):
        self.sema.release()

    def get_password(self):
        length = self.options["length"]
        nwords = self.options["nwords"]
        minchars = self.options["minchars"]
        maxchars = self.options["maxchars"]

        # List of words to choose from.
        words = list(self.emitted)

        if len(words) > nwords and len(self.words) > nwords:
            # Choose from the nwords most common words in the database.
            counts = sorted(zip(list(self.words.values()), list(self.words.keys())))
            words = [w for (_count, w) in counts[-nwords:]]

        self.cr.shuffle(words)
        # Select the first length unused words from the shuffled list.
        words = [w for w in words
                   if minchars <= len(w) <= maxchars and
                      w not in self.used]
        words = words[0:length]

        # Remember that we used them.
        self.used |= set(words)
        # Randomize the selected words a bit.
        self.tweak(words)

        extras = list(self.punct if self.options["punctuation"] else set() |
                      self.digits if self.options["digits"] else set())
        if extras:
            for i in range(len(words)-1, 0, -1):
                self.cr.shuffle(extras)
                words[i:i] = extras[0]
            words = "".join(words)
        else:
            # Otherwise, just use spaces.
            words = " ".join(words)
        return words

    def tweak(self, words):
        """Randomize the individual words a bit.

        Probability of tweakage goes up as the number of words is reduced.
        """
        length = len(words)
        extras = list(self.punct if self.options["punctuation"] else set() |
                      self.digits if self.options["digits"] else set())
        if not extras:
            extras = list(string.uppercase)
        for (i, word) in enumerate(words):
            word = list(words[i])
            for j in range(len(word) - 1, -1, -1):
                # 20% chance to convert a letter to upper case.
                if self.cr.random() < 0.4 / length:
                    word[j] = word[j].upper()
                # 15% chance to insert something between letters.
                if extras and self.cr.random() < 0.3 / length:
                    self.cr.shuffle(extras)
                    word[j:j] = extras[0]
            words[i] = "".join(word)

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
            self.cr.shuffle(raw)
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
        words = [w for (_count, w) in counts[-nwords:]]
        self.emitted = set(words)

    def load_pfile(self):
        if os.path.exists(self.pfile):
            # Bad word list is in separate plain text file.
            with open(self.pfile, "rb") as pfile:
                (self.msg_ids, self.words, self.emitted) = pickle.load(pfile)

        if os.path.exists(self.bfile):
            with open(self.bfile) as bfile:
                self.bad |= set([w.strip() for w in bfile])

    def save_pfile(self):
        with open(self.pfile, "wb") as pfile:
            pickle.dump((self.msg_ids, self.words, self.emitted), pfile)
        # Save bad words in a plain text file so we can retain them if
        # we decide to toss the pickle file, and so we can easily edit
        # the bad words list.
        with open(self.bfile, "w") as bfile:
            for word in sorted(self.bad):
                bfile.write(word+"\n")

    def process_text(self, text):
        "must be called inside a 'with' statement."
        self.consider_words(set(text.split()))

    def consider_words(self, candidates):
        lowercase = set(string.ascii_lowercase)
        for word in candidates:
            wset = set(word)
            # Though we live in a Unicode world, I really only want stuff
            # *I* can type as a password, so restrict words to ASCII
            # lowercase. There's probably a more general way to accommodate
            # the population of users who can easily type non-ASCII text,
            # but I'll let someone else deal with that.
            if (word in self.bad or
                len(word) < 4 or
                wset & lowercase != wset):
                continue
            self.words[word] = self.words.get(word, 0) + 1
            if (word not in self.emitted and
                self.words[word] >= 10 and
                len(self.words) >= 500):
                counts = sorted(self.words.values())
                min_index = len(self.words) - self.options["nwords"]
                if counts.index(self.words[word]) >= min_index:
                    self.emitted.add(word)

    def print_statistics(self):
        print("message ids:", len(self.msg_ids))
        print("all words:", len(self.words))
        print("common words:", len(self.emitted), end=' ')
        bits = math.log(len(self.emitted), 2) if self.emitted else 0
        print("entropy:", "%.2f" % bits, "bits")
        print("'bad' words:", len(self.bad))
        print("seen uids:", len(self.uids), end=' ')
        if self.uids:
            print(min(self.uids), "->", max(self.uids), end=' ')
        print()

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
        print(msg, file=sys.stderr)
        print(file=sys.stderr)
    print(__doc__ % globals(), file=sys.stderr)

def main(args):
    options = {
        "server": None,
        "user": None,
        "password": None,
        "folder": None,
        "length": None,
        "nwords": None,
        "verbose": None,
        "digits": None,
        "punctuation": None,
        "minchars": None,
        "maxchars": None,
        "editing-mode": None,
        "hash": None,
        "prompt": None,
        "gui": None,
        "unittests": None,
        }
    getters = {
        "server": "get",
        "user": "get",
        "password": "get",
        "prompt": "get",
        "folder": "get",
        "length": "getint",
        "nwords": "getint",
        "verbose": "getboolean",
        "digits": "getboolean",
        "punctuation": "getboolean",
        "minchars": "getint",
        "maxchars": "getint",
        "editing-mode": "get",
        "hash": "getboolean",
        "gui": "getboolean",
        "unittests": "getboolean",
        }

    configfile = None
    generate_n = 0
    all_args = args[:]
    opts, args = getopt.getopt(args, "s:u:p:f:c:g:HhvGn",
                               ["gui", "help"])
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
        elif opt == "-g":
            generate_n = int(arg)
        elif opt == "-n":
            options["prompt"] = False
        elif opt in ("-G", "--gui"):
            options["gui"] = True
            run_gui(all_args)
            return 0
        elif opt == "-c":
            configfile = arg
        elif opt == "-H":
            options["hash"] = True
        elif opt in ("-h", "--help"):
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

        if options["length"] is None:
            options["length"] = 4

        if options["nwords"] is None:
            options["nwords"] = 2048

        if options["maxchars"] is None:
            options["maxchars"] = 999

        if options["minchars"] is None:
            options["minchars"] = 3

        if options["punctuation"] is None:
            options["punctuation"] = True

        if options["digits"] is None:
            options["digits"] = True

        if options["editing-mode"] is None:
            options["editing-mode"] = "emacs"

        if options["hash"] is None:
            options["hash"] = False

        if options["prompt"] is None:
            options["prompt"] = True

        if options["gui"] is None:
            options["gui"] = False

        if options["unittests"] is None:
            options["unittests"] = False

    # if None in options.values():
    #     usage("Server, user, password and folder are all required.")
    #     return 1

    polly = Polly(options)

    # Just generate some passwords
    if generate_n:
        if options["hash"]:
            def encrypt(p):
                return "$dummy$" + binascii.hexlify(p)
        else:
            encrypt = lambda x: x
        with polly:
            for _ in range(generate_n):
                print(encrypt(polly.get_password()))
        return 0

    readline.parse_and_bind('tab: complete')
    readline.parse_and_bind('set editing-mode %s' % options["editing-mode"])
    histfile = os.path.expanduser('~/.polly.rc')
    try:
        readline.read_history_file(histfile)
    except IOError:
        pass
    atexit.register(readline.write_history_file, histfile)

    try:
        get_commands(polly)
    except KeyboardInterrupt:
        pass
    finally:
        if not options["gui"]:
            polly.save_pfile()

    return 0

def get_commands(polly):
    try:
        while True:
            prompt = "? " if polly.options["prompt"] else ""
            try:
                command = input(prompt)
            except EOFError:
                break
            command = command.strip()
            if not command:
                continue
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
                    note("Punctuation? {} Digits? {}".format(
                        self.options["punctuation"], self.options["digits"]),
                         self.options["verbose"])
                    for _ in range(count):
                        passwd = polly.get_password()
                        print(repr(passwd), file=sys.stderr)
                        sys.stdout.write(passwd+"\n")
                        sys.stdout.flush()
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
                    print("verbose:", polly.options["verbose"])
            elif command == "exit":
                break
            elif command in ("help", "?"):
                usage()
            else:
                if command == "bad":
                    with polly:
                        for word in rest.split():
                            polly.bad_polly(word)
                elif command == "dict":
                    with polly:
                        not_really_words = " ".join(polly.get_not_words(rest))
                        print(textwrap.fill(not_really_words))
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

def note(msg, verbose=True):
    if verbose:
        sys.stderr.write("\n%s\n? " % msg)
        sys.stderr.flush()

def read_imap(polly):
    while True:
        read_loop(polly)
        time.sleep(600)

def read_loop(polly):
    with polly:
        options = polly.options.copy()
        msg_ids = polly.msg_ids.copy()
        seen_uids = polly.uids

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

        uids = set(data[0].split()) - seen_uids
        if options["verbose"]:
            note("search successful - %d uids returned." % len(uids))
        if uids:
            note("Will process %d uids" % len(uids))
        for uid in uids:
            seen_uids.add(uid)
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
            text = get_body(message)
            if not text:
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

def run_gui(args):
    # Re-run as a subprocess which we will talk to, need to run it
    # without the gui though.
    for garg in ("-G", "--gui"):
        while garg in args:
            args.remove(garg)
    args = ["python", sys.argv[0], "-n"] + args
    pipe = subprocess.Popen(args, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, bufsize=1)
    root = tkinter.Tk()
    app = Application(pipe, master=root)
    app.mainloop()
    root.destroy()
    pipe.kill()

class Application(tkinter.Frame):
    def __init__(self, pipe, master=None):
        tkinter.Frame.__init__(self, master)
        self.pipe = pipe
        self.pack()
        self.create_widgets()

    def run_command(self):
        print(">>", self.entry.get(), "->", end=' ')
        print(self.entry.get().strip(), file=self.pipe.stdin)
        self.pipe.stdin.flush()
        print(self.pipe.stdout.readline())

    def handle_key(self, event):
        if event.char == "\r":
            self.run_command()

    def create_widgets(self):
        self.entry = tkinter.Entry(self)
        self.entry.pack(side=tkinter.TOP)
        self.entry.bind("<Key>", self.handle_key)

        self.exit = tkinter.Button(self)
        self.exit["text"] = "Quit"
        self.exit.pack(side=tkinter.TOP)
        self.exit["command"] = self.quit

class IMAP(imaplib.IMAP4_SSL):
    def __init__(self, server):
        imaplib.IMAP4_SSL.__init__(self, server)

    def __enter__(self):
        return self

    def __exit__(self, _type, _value, _traceback):
        self.logout()

# get_charset and get_body are from:
#  http://ginstrom.com/scribbles/2007/11/19/parsing-multilingual-email-with-python/

def get_charset(message, default="ascii"):
    """Get the message charset"""

    if message.get_content_charset():
        return message.get_content_charset()

    if message.get_charset():
        return message.get_charset()

    return default

def get_body(message):
    """Get the body of the email message"""

    if message.is_multipart():
        #get the plain text version only
        text_parts = [part
                      for part in typed_subpart_iterator(message,
                                                         'text',
                                                         'plain')]
        body = []
        for part in text_parts:
            charset = get_charset(part, get_charset(message))
            body.append(str(part.get_payload(decode=True),
                                charset,
                                "replace"))

        return "\n".join(body).strip()

    else: # if it is not multipart, the payload will be a string
          # representing the message body
        body = str(message.get_payload(decode=True),
                       get_charset(message),
                       "replace")
        return body.strip()

# def get_text(message):
#     maintype = message.get_content_maintype()
#     if maintype == 'multipart':
#         for part in message.get_payload():
#             if part.get_content_maintype() == 'text':
#                 charset = part.get_charset()
#                 payload = part.get_payload()
#                 if charset is not None:
#                     note(">> %s" % charset)
#                     return charset.to_splittable(part.get_payload())
#                 return payload
#     elif maintype == 'text':
#         charset = message.get_charset()
#         payload = message.get_payload()
#         if charset is not None:
#             note(">> %s" % charset)
#             return charset.to_splittable(message.get_payload())
#         return payload
#     else:
#         return ""

if __name__ == "__main__":
    main(sys.argv[1:])
