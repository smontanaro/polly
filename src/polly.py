#!/usr/bin/env python

"""polly - build a corpus from an IMAP folder and use it to generate passwords.

usage: %(PROG)s args ...

Note that command line args are processed in order, so later args will
override earlier. In particular, you probably want to specify the
config file (-c flag) earlier so you can override values it contains
from the command line.

If the -g flag is given, polly will print N passwords, then exit
without starting a command loop. If the -c flag is given, options are
read from the named config file.  The -L option is used to control the
logging level.

When generating passwords, you can specify that they are to be hashed
using the -H flag. You must also give the type of hash to use. Any
hash type in Python's hashlib.algorithm tuple is acceptable.

The config file has a single section, Polly. Within that section, any of the
following options may be defined.

Options
-------

digits         - when True, allow digits between words (default False)
edit-mode      - editor mode for readline (default 'emacs')
folder         - comma-separated list of folder(s) to check for
                 messages (required)
hash           - emit passwords using $dummy$hex instead of plain text
                 passwords (for strength testing using JohnTheRipper)
length         - number of words used to construct passwords (default 4)
lookback       - number of days to look back for messages (default 50)
maxchars       - length of longest word to use when generating passwords
                 (default 999)
minchars       - length of shortest word to use when generating passwords
                 (default 3)
nwords         - n common words to use when considering candidates
                 (default 2048)
password       - the password for the IMAP server (required)
punctuation    - when True, allow punctuation between words (default False)
server         - the hostname of the IMAP server (required)
user           - the login name on the IMAP server (required)
verbose        - set to string value of log level (default FATAL)

Commands
--------

add dictfile n - add n random words from dictfile
bad word ...   - mark one or more words as bad
dict dictfile  - report words not present in dictfile
exit/quit/^D   - quit the program
good dictfile  - declare the words contained as unconditionally "good"
help or ?      - print this help
password [n]   - generate n passwords (default 1)
read           - read messages from the IMAP server in a second thread
rebuild        - rebuild the 'good' words list
save           - write the pickle save file and bad words file
stat           - print some simple statistics about the collected words
verbose        - toggle verbose flag

Readline support is enabled, with input history saved in ~/.polly.rc.

"""

import atexit
import binascii
import bz2
import configparser
import datetime
import email
from email.iterators import typed_subpart_iterator
import getopt
import gzip
import imaplib
import logging
import math
import os
import pickle
import queue
import random
import readline
import ssl
import string
import sys
import textwrap
import threading
import time

import imapclient

PROG = os.path.split(sys.argv[0])[1]

LOG_FORMAT = "%(asctime)-15s %(levelname)s %(message)s"

PUNCT = set(string.punctuation)
UPPER = set(string.ascii_uppercase)
LOWER = set(string.ascii_lowercase)
DIGITS = set(string.digits)

class Polly:
    "Workhorse of the system."
    def __init__(self, options):
        self._log_fp = None
        self.log_queue = queue.Queue()
        self.reader = None
        self.options = options
        self.msg_ids = set()
        self.words = {}
        self.emitted = set()
        self.bad = set()
        self.uids = set()
        self.good_words = set()
        self.log = logging.getLogger("polly")
        self.log.setLevel(options["verbose"])
        self.pfile = options["picklefile"]
        pkl_dir = os.path.dirname(self.pfile)
        self.bfile = os.path.join(pkl_dir, "polly.bad")
        self.load_pfile()
        # Workers will acquire/release Polly to operate on internal
        # data. See __enter__ and __exit__.
        self.sema = threading.Semaphore()
        # Words already used in a password on this run.
        self.used = set()
        # Cryptographically secure random number generator.
        if self.options["unittests"]:
            # generate predictable set of "random" values for testing.
            # pylint: disable=protected-access
            self.rng = random._inst
            self.rng.seed(100)
        else:
            self.rng = random.SystemRandom()

    @property
    def log_fp(self):
        "property to get/set logfile and close when necessary."
        return self._log_fp
    @log_fp.setter
    def log_fp(self, log_fp):
        if self._log_fp is not None and not self._log_fp.closed:
            self._log_fp.close()
        self._log_fp = log_fp

    def __enter__(self):
        self.sema.acquire()
        return self

    def __exit__(self, _type, _value, _traceback):
        self.sema.release()

    def get_password(self):
        "Generate a password."
        length = self.options["length"]
        nwords = self.options["nwords"]
        minchars = self.options["minchars"]
        maxchars = self.options["maxchars"]

        # List of words to choose from.
        words = list(self.emitted)

        if len(words) > nwords and len(self.words) > nwords:
            # Choose from the nwords most common words in the database.
            counts = sorted(zip(self.words.values(), self.words.keys()))
            words = [w for (_count, w) in counts[-nwords:]]

        words = sorted(words)
        self.rng.shuffle(words)
        # Select the first length unused words from the shuffled list.
        words = [w for w in words
                   if minchars <= len(w) <= maxchars and
                      w not in self.used]
        words = words[0:length]

        # Remember that we used them.
        self.used |= set(words)
        # Randomize the selected words a bit.
        self.tweak(words)

        extras = set()
        if self.options["punctuation"]:
            extras |= PUNCT
        if self.options["digits"]:
            extras |= DIGITS
        extras = sorted(extras)
        if not extras:
            extras = [" "]
        for i in range(len(words)-1, 0, -1):
            self.rng.shuffle(extras)
            words[i:i] = extras[0]
        passwd = "".join(words)
        if self.options["hash"]:
            passwd = "$dummy$" + str(binascii.hexlify(bytes(passwd,
                                                            encoding="utf-8")),
                                     encoding="utf-8")
        return passwd

    def tweak(self, words):
        """Randomize the individual words a bit.

        Probability of tweakage goes up as the number of words is reduced.
        """
        length = len(words)
        extras = set()
        if self.options["punctuation"]:
            extras |= PUNCT
        if self.options["digits"]:
            extras |= DIGITS
        extras = sorted(extras)
        for (i, word) in enumerate(words):
            word = list(words[i])
            for j in range(len(word) - 1, -1, -1):
                # 20% chance to convert a letter to upper case.
                if self.options["upper"] and self.rng.random() < 0.4 / length:
                    word[j] = word[j].upper()
                # 15% chance to insert something between letters.
                if self.rng.random() < 0.3 / length and extras:
                    self.rng.shuffle(extras)
                    word[j:j] = extras[0]
            words[i] = "".join(word)

    def bad_polly(self, word):
        "Add a word to the bad list."
        self.bad.add(word)
        self.emitted.discard(word)

    def get_not_words(self, dictfile):
        """Retrieve word-like things which might not really be words.

        dictfile is our authority.  We return any in self.emitted
        which don't appear in dictfile, minus any in our set of
        explicitly good words

        """
        if not os.path.exists(dictfile):
            self.log.error("%r does not exist", dictfile)
            return []
        with open(dictfile) as dictfp:
            raw = [w.strip().lower() for w in dictfp]
            dict_words = set(raw)
            for suffix in ("ing", "ed", "es", "s", "ies"):
                dict_words |= {w+suffix for w in raw}
            return sorted(self.emitted - dict_words - self.good_words)

    def add_bad_words(self, arg):
        "Extend list of bad words."
        for word in arg.split():
            self.bad_polly(word)

    def check_dict(self, arg):
        "Check dictionary for missing words."
        not_really_words = " ".join(self.get_not_words(arg))
        print(textwrap.fill(not_really_words))

    def add_good_words(self, arg):
        "Extend list of explicitly good words."
        dictfile = arg
        good = set(word.strip() for word in open(dictfile))
        self.good_words |= good

    def add_words(self, arg):
        "Add words to our collection."
        dictfile, nwords = arg.split()
        nwords = int(nwords)
        if not os.path.exists(dictfile):
            self.log.error("%r does not exist", dictfile)
            return
        upper_and_punct = PUNCT | UPPER
        with open(dictfile) as dictfp:
            raw = [w.strip()
                     for w in dictfp
                       if (not set(w) & upper_and_punct) and len(w) > 4]
            self.rng.shuffle(raw)
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

    def rebuild(self, _arg):
        "Rebuild self.emitted from self.words."
        counts = sorted((self.words[w], w) for w in self.words
                            if (len(w) >= self.options["minchars"] and
                                w not in self.bad))
        self.emitted = set(w for (_count, w) in counts[-self.options["nwords"]:])

    def load_pfile(self):
        "Read state from the pickle file."
        if os.path.exists(self.pfile):
            with open(self.pfile, "rb") as pfile:
                (self.msg_ids, self.words, self.emitted,
                 self.uids) = pickle.load(pfile)

        # Bad word list is in separate plain text file.
        if os.path.exists(self.bfile):
            with open(self.bfile) as bfile:
                self.bad |= {w.strip() for w in bfile}

    def save_pfile(self, _arg):
        "Write state to pickle file."
        with open(self.pfile, "wb") as pfile:
            pickle.dump((self.msg_ids, self.words, self.emitted, self.uids),
                        pfile)

        # Save bad words in a plain text file so we can retain them if
        # we decide to toss the pickle file, and so we can easily edit
        # the bad words list.
        with open(self.bfile, "w") as bfile:
            for word in sorted(self.bad):
                bfile.write(word+"\n")

        # Make sure log records are flushed.
        if self.log_fp is not None and not self.log_fp.closed:
            self.log_fp.flush()

    def consider_words(self, candidates):
        "Filter out tokens which are non-ascii or look like HTML tags."
        html = set()
        nemitted = len(self.emitted)
        for word in candidates:
            wset = set(word)
            if (word in self.bad or
                len(word) < self.options["minchars"] or
                # Only lower case ASCII - no numbers, punct, accents,
                # HTML tags ...
                wset & LOWER != wset):
                continue
            self.words[word] = self.words.get(word, 0) + 1
            len_words = len(self.words)
            if (word not in self.emitted and
                self.words[word] >= 7 and
                len_words >= 250):
                counts = sorted(self.words.values())
                if (counts.index(self.words[word]) >=
                    len_words - self.options["nwords"]):
                    self.emitted.add(word)
        return (len(self.emitted) - nemitted, len(html))

    def print_statistics(self, _arg):
        "Print some summary details."
        print(f"message ids: {len(self.msg_ids)}")
        print(f"all words: {len(self.words)}")
        print(f"common words: {len(self.emitted)}", end=' ')
        bits = math.log(len(self.emitted), 2) if self.emitted else 0
        print(f"entropy: {bits * self.options['length']:.3f} bits")
        print(f"'bad' words: {len(self.bad)}")
        print(f"seen uids: {len(self.uids)}", end=' ')
        if self.uids:
            print(f"{min(self.uids)} -> {max(self.uids)}", end=' ')
        print()

    def start_reader(self, _arg):
        "Fire up the IMAP reader thread."
        if self.reader is None or not self.reader.is_alive():
            self.log.debug("starting IMAP thread.")
            self.reader = threading.Thread(target=self.read_imap,
                                            name="imap-thread",
                                            args=())
            self.reader.daemon = True
            self.reader.start()

    def get_commands(self):
        "Command loop."
        # Add new commands here as a method which takes a single argument.
        commands = {
            "read": self.start_reader,
            "stat": self.print_statistics,
            "rebuild": self.rebuild,
            "save": self.save_pfile,
            "help": usage,
            "?": usage,
            "password": self.generate_passwords,
            "bad": self.add_bad_words,
            "dict": self.check_dict,
            "add": self.add_words,
            "good": self.add_good_words,
            "option": self.process_option,
            "sleep": self.sleep, # just for testing...
        }
        try:
            while True:
                # Grab whatever log records we can from the IMAP thread.
                try:
                    while True:
                        (level, args, kwds) = self.log_queue.get_nowait()
                        self.log.log(level, *args, **kwds)
                except queue.Empty:
                    pass

                prompt = "? " if self.options["prompt"] else ""
                command = input(prompt).strip()
                if not command:
                    continue
                try:
                    command, arg = command.split(None, 1)
                except ValueError:
                    arg = ""
                if command in ("exit", "quit"):
                    break

                with self:
                    cmdfunc = commands.get(command)
                    if cmdfunc is not None:
                        cmdfunc(arg)
                        continue
                    self.log.error("Unrecognized command %r", command)
        except (EOFError, KeyboardInterrupt):
            pass

        self.log.info("Awk! Goodbye...")

    def sleep(self, arg):
        "sleep for a bit - just to support testing."
        time.sleep(float(arg))

    def process_option(self, arg):
        "Show or set options."
        if not arg.strip():
            for option in sorted(self.options):
                value = self.options[option]
                if option == "folder":
                    value = ",".join(value)
                print(f"option {option} {value}")
        else:
            option, value = arg.split()
            if option == "verbose":
                value = value.upper()
                if hasattr(logging, value):
                    self.options["verbose"] = value
                    self.log.setLevel(self.options["verbose"])
                else:
                    self.log.error("%r is not a valid log level name", value)
            elif option == "logfile":
                self.options["logfile"] = value
                self.log_fp = smart_open(self.options["logfile"], "at")
                logging.basicConfig(format=LOG_FORMAT, force=True,
                                    stream=self.log_fp)
                self.log = logging.getLogger("polly")
            elif option in ("length", "maxchars", "nwords", "maxchars",
                            "minchars", "lookback"):
                self.options[option] = int(value)
            elif option in ("digits", "punctuation", "upper", "hash", "prompt",
                            "unittests"):
                value = value.lower()
                if value in ("true", "false"):
                    self.options[option] = value == "true"
                else:
                    self.log.error("%r is not in (true, false)", value)
            elif option == "editing-mode":
                value = value.lower()
                if value in ("emacs", "vi"):
                    self.options[option] = value
                else:
                    self.log.error("%r is not in (emacs, vi)", value)
            elif option == "folder":
                self.options[option] = [f.strip() for f in value.split(",")]
            else:
                self.log.error("Don't know how to set option %r", option)

    def generate_passwords(self, arg):
        "Generate COUNT passwords."
        count = int(arg) if arg else 1
        nwords = self.options["nwords"]
        if (len(self.emitted) > nwords and
            len(self.words) > nwords):
            self.log.info("Using %d most common words.", nwords)
        self.log.debug("Punctuation? %s Digits? %s Upper? %s",
                       self.options["punctuation"],
                       self.options["digits"],
                       self.options["upper"])
        for _ in range(count):
            passwd = self.get_password()
            sys.stdout.write(passwd+"\n")
            sys.stdout.flush()

    def read_imap(self):
        "Thread target."
        try:
            while True:
                self.read_loop()
                time.sleep(150)
        finally:
            self.reader = None

    def log_thread(self, level, *args, **kwds):
        "helper"
        self.log_queue.put((getattr(logging, level), args, kwds))

    def read_loop(self):
        "Basic loop over IMAP connection."
        with self:
            options = self.options.copy()

        ssl_context = ssl.create_default_context()
        # don't check if certificate hostname doesn't match target hostname
        ssl_context.check_hostname = False
        # don't check if the certificate is trusted by a certificate authority
        ssl_context.verify_mode = ssl.CERT_NONE

        # Reference the verbose parameter through the options dict so the
        # user can toggle the setting on-the-fly.
        with imapclient.IMAPClient(options["server"], use_uid=True,
                                   ssl_context=ssl_context) as server:
            try:
                server.login(options["user"], options["password"])
            except imapclient.exceptions.IMAPClientError:
                self.log_thread("ERROR", "login failed. check your credentials.")
                self.log_thread("ERROR", "Exiting read loop early")
                return
            self.log_thread("TRACE", "login successful.")
            nnew = 0
            for folder in options["folder"]:
                try:
                    nnew += self.select_and_read(server, folder)
                except (ConnectionError, imaplib.IMAP4.error) as abt:
                    self.log_thread("ERROR", "Server read error %s", abt)
                    self.log_thread("ERROR", "Exiting read loop early")
                    return
            self.log_thread("WARNING", "Finished. All new msgs: %d", nnew)

    def select_and_read(self, server, folder):
        "Check folder on server for new messages."
        with self:
            options = self.options.copy()
            msg_ids = self.msg_ids.copy()
            seen_uids = self.uids.copy()
        try:
            server.select_folder(folder)
            self.log_thread("DEBUG", "select folder %r.", folder)
            nnew = 0
            self.log_thread("DEBUG", "look back %d days.", options["lookback"])
            start = (datetime.datetime.now() -
                     datetime.timedelta(days=options["lookback"]))
            uids = server.search([b"SINCE", start.date()])
            uids = [(folder, uid) for uid in uids]
            uids = list(set(uids) - seen_uids)
            nuids = len(uids)
            self.log_thread("WARNING", "%s: %d new UIDs returned.",
                            folder, nuids)
            while uids:
                (chunk, uids) = (uids[:100], uids[100:])
                chunk = [uid for (_folder, uid) in chunk]
                result = server.fetch(chunk, [b'BODY.PEEK[TEXT]', b'ENVELOPE'])
                for uid in chunk:
                    seen_uids.add((folder, uid))
                    nnew += self.process_one_message(uid,
                                                     result[uid][b"BODY[TEXT]"],
                                                     result[uid][b"ENVELOPE"],
                                                     msg_ids)
                if nnew % 100 == 0:
                    self.log_thread("WARNING", "%s new msgs: %d/%d",
                                    folder, nnew, nuids)
                    with self:
                        self.msg_ids |= msg_ids
                        self.uids |= seen_uids
                elif nnew % 10 == 0:
                    self.log_thread("INFO", "%s new msgs: %d", folder, nnew)
            self.log_thread("WARNING", "%s new msgs: %d", folder, nnew)
            return nnew
        finally:
            with self:
                self.msg_ids |= msg_ids
                self.uids |= seen_uids

    def process_one_message(self, uid, body, envelope, msg_ids):
        "Handle one message"
        msg = email.message_from_bytes(body)
        self.log_thread("TRACE", "%s", envelope)
        msg_id = envelope.message_id
        if msg_id in msg_ids:
            # Already processed
            return 0
        self.log_thread("DEBUG", "UID: %s, Date: %s, Message-ID: %r",
                        uid, envelope.date, msg_id)
        msg_ids.add(msg_id)

        # We haven't seen this message yet. Process its text
        # (well, the first text/plain part or the plain text of
        # the first text/html part we come across).
        text = self.get_body(msg)
        if not text:
            return 0

        with self:
            nwords, nhtml = self.consider_words(set(text.split()))
            if nwords or nhtml:
                self.log_thread("DEBUG", "%d new words from %s (%d HTML tags).",
                                nwords, msg_id, nhtml)

        return 1

    # get_charset and get_body are adapted from:
    #   http://ginstrom.com/scribbles/2007/11/19/parsing-multilingual-email-with-python/

    # pylint: disable=no-self-use
    def get_charset(self, message, default="ascii"):
        """Get the message charset"""

        charset = (message.get_content_charset() or
                   message.get_charset() or
                   default)
        return charset

    def get_body(self, message):
        """Get the body of the email message"""

        if message.is_multipart():
            #get the plain text version only
            body = []
            # MIME type order is important here...
            for (type_, subtype) in (("text", "plain"), ("text", "html")):
                for part in typed_subpart_iterator(message, type_, subtype):
                    charset = self.get_charset(part, self.get_charset(message))
                    payload = str(part.get_payload(decode=True), charset,
                                  "replace")
                    self.log.trace("%s/%s charset: %s, payload: %s...",
                                   type_, subtype, charset, payload[0:50])
                    body.append(payload)
                if body:
                    # Done if we got something for text/plain...
                    break
            return "\n".join(body).strip()

        # if it is not multipart, the payload will be a string
        # representing the message body
        body = str(message.get_payload(decode=True),
                   self.get_charset(message),
                   "replace")
        return body.strip()

# Adapted from: https://stackoverflow.com/questions/2183233/
def add_log_level(name, num, methodname=None):
    """
    Comprehensively adds a new logging level to the `logging` module and the
    currently configured logging class.

    `name` becomes an attribute of the `logging` module with the value
    `num`. `methodname` becomes a convenience method for both `logging`
    itself and the class returned by `logging.getLoggerClass()` (usually just
    `logging.Logger`). If `methodname` is not specified, `name.lower()` is
    used.

    To avoid accidental clobberings of existing attributes, this method will
    raise an `AttributeError` if the level name is already an attribute of the
    `logging` module or if the method name is already present

    Example
    -------
    >>> addLoggingLevel('TRACE', logging.DEBUG - 5)
    >>> logging.getLogger(__name__).setLevel("TRACE")
    >>> logging.getLogger(__name__).trace('that worked')
    >>> logging.trace('so did this')
    >>> logging.TRACE
    5

    """
    if methodname is None:
        methodname = name.lower()

    if hasattr(logging, name):
        raise AttributeError(f'{name} already defined in logging module')
    if hasattr(logging, methodname):
        raise AttributeError(f'{methodname} already defined in logging module')
    if hasattr(logging.getLoggerClass(), methodname):
        raise AttributeError(f'{methodname} already defined in logger class')

    # This method was inspired by the answers to Stack Overflow post
    # http://stackoverflow.com/q/2183233/2988730, especially
    # http://stackoverflow.com/a/13638084/2988730
    def log_for_level(self, message, *args, **kwargs):
        if self.isEnabledFor(num):
            # pylint: disable=protected-access
            self._log(num, message, args, **kwargs)
    def log_to_root(message, *args, **kwargs):
        logging.log(num, message, *args, **kwargs)

    logging.addLevelName(num, name)
    setattr(logging, name, num)
    setattr(logging.getLoggerClass(), methodname, log_for_level)
    setattr(logging, methodname, log_to_root)

def usage(msg=""):
    "User help."
    if msg:
        print(msg, file=sys.stderr)
        print(file=sys.stderr)
    print(__doc__ % globals(), file=sys.stderr)

def read_config(configfile, options):
    "Process sections in config file."
    # Fill in what wasn't given on the command line.
    config = configparser.RawConfigParser()
    config.read(configfile)
    for key in options:
        try:
            value = getattr(config, GETTERS[key])("Polly", key)
        except configparser.NoOptionError:
            pass
        else:
            if key == "folder":
                value = [f.strip() for f in value.split(",")]
            elif key == "verbose":
                value = value.upper()
            options[key] = value

def smart_open(filename, mode="r"):
    "use file extension to decide how to open filename"
    if filename.endswith(".gz"):
        return gzip.open(filename, mode)
    if filename.endswith(".bz2"):
        return bz2.open(filename, mode)
    return open(filename, mode)

GETTERS = {
    "digits": "getboolean",
    "editing-mode": "get",
    "folder": "get",
    "hash": "getboolean",
    "length": "getint",
    "logfile": "get",
    "lookback": "getint",
    "maxchars": "getint",
    "minchars": "getint",
    "nwords": "getint",
    "password": "get",
    "picklefile": "get",
    "prompt": "get",
    "punctuation": "getboolean",
    "server": "get",
    "unittests": "getboolean",
    "upper": "getboolean",
    "user": "get",
    "verbose": "get",
    }

def main(args):
    "Where it all starts."

    # More verbose than DEBUG...
    add_log_level("TRACE", logging.DEBUG - 5)

    # Options related to the IMAP connection have no default, hence
    # None.  They must be specified on the command line or in the
    # config file if you plan to chat with the server.
    options = {
        "digits": True,
        "editing-mode": "emacs",
        "folder": None,
        "hash": False,
        "length": 4,
        "logfile": "/dev/stderr",
        "lookback": 50,
        "maxchars": 999,
        "minchars": 3,
        "nwords": 2048,
        "password": None,
        "picklefile": os.path.join(os.getcwd(), "polly.pkl"),
        "prompt": True,
        "punctuation": True,
        "server": None,
        "unittests": False,
        "upper": True,
        "user": None,
        "verbose": "FATAL",
        }

    generate_n = 0
    configfile = None
    opts, _args = getopt.getopt(args, "s:u:p:f:c:g:HhL:nl:", ["help"])
    for opt, arg in opts:
        if opt == "-c":
            configfile = arg
            try:
                with open(configfile) as _cfg:
                    pass
            except OSError:
                log = logging.getLogger("polly")
                log.fatal("Specified config file %s does not exist or"
                          " is not readable.",
                          configfile)
                return 1
            else:
                read_config(configfile, options)
        elif opt in ("-h", "--help"):
            usage()
            return 0
        elif opt == "-u":
            options["user"] = arg
        elif opt == "-p":
            options["password"] = arg
        elif opt == "-f":
            options["folder"] = arg
        elif opt == "-s":
            options["server"] = arg
        elif opt == "-g":
            generate_n = int(arg)
        elif opt == "-L":
            options["verbose"] = arg
        elif opt == "-l":
            options["logfile"] = arg
        elif opt == "-n":
            options["prompt"] = False
        elif opt == "-H":
            options["hash"] = True

    log = smart_open(options["logfile"], "at")
    logging.basicConfig(format=LOG_FORMAT, force=True, stream=log)

    polly = Polly(options)
    polly.log_fp = log

    # Just generate some passwords
    if generate_n:
        for _ in range(generate_n):
            print(polly.get_password())
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
        polly.get_commands()
    finally:
        polly.save_pfile(None)

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
