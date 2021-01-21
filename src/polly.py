#!/usr/bin/env python

"""polly - build a corpus from an IMAP folder and use it to generate passwords.

usage: %(PROG)s -s server -u user -p password -f folder [ -g N [ -H what ] ] \
        [ -c config ] [ -L level ]

The server, user, password and folder flags are required unless they
are specified in the config file.  If the -g flag is given, polly will
print N passwords, then exit without starting a command loop. If the
-c flag is given, options are read from the named config file. The -s,
-u, -p, and -f flags take precedence over the values defined in the
config file. The -L option is used to control the logging level.

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
verbose        - set to string value of log level (default FATAL)
punctuation    - when True, allow punctuation between words (default False)
digits         - when True, allow digits between words (default False)
lookback       - number of days to look back for messages (default 50)
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
from configparser import RawConfigParser, NoOptionError
import datetime
import email
from email.iterators import typed_subpart_iterator
import getopt
import imaplib
import logging
import math
import os
import pickle
import random
import re
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
        words = "".join(words)
        return words

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
        which don't appear in dictfile, minus any in our set of explicitly good words

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

    def add_words(self, dictfile, nwords):
        "Add words to our collection."
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

    def rebuild(self):
        "Rebuild self.emitted from self.words."
        counts = sorted([(self.words[w], w)
                             for w in self.words if w not in self.bad])
        nwords = self.options["nwords"]
        words = [w for (_count, w) in counts[-nwords:]]
        self.emitted = set(words)

    def load_pfile(self):
        "Read state from the pickle file."
        if os.path.exists(self.pfile):
            # Bad word list is in separate plain text file.
            try:
                with open(self.pfile, "rb") as pfile:
                    (self.msg_ids, self.words, self.emitted, self.uids) = pickle.load(pfile)
            except ValueError:
                with open(self.pfile, "rb") as pfile:
                    (self.msg_ids, self.words, self.emitted) = pickle.load(pfile)
                    self.uids = set()

        if os.path.exists(self.bfile):
            with open(self.bfile) as bfile:
                self.bad |= {w.strip() for w in bfile}

    def save_pfile(self):
        "Write state to pickle file."
        with open(self.pfile, "wb") as pfile:
            pickle.dump((self.msg_ids, self.words, self.emitted, self.uids), pfile)

        # Save bad words in a plain text file so we can retain them if
        # we decide to toss the pickle file, and so we can easily edit
        # the bad words list.
        with open(self.bfile, "w") as bfile:
            for word in sorted(self.bad):
                bfile.write(word+"\n")

    def process_text(self, text):
        "must be called inside a 'with' statement."
        return self.consider_words(set(text.split()))

    def consider_words(self, candidates):
        lowercase = LOWER
        html = set()
        nwords = len(self.emitted)
        for raw in candidates:
            word = re.sub(r"</?[^ >]+>\s*", "", raw)
            if not word:
                # word was an HTML tag.
                self.log.debug("HTML: %s", raw)
                html.add(raw)
                continue
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
        return (len(self.emitted) - nwords, len(html))

    def print_statistics(self):
        "Print some summary details."
        print(f"message ids: {len(self.msg_ids)}")
        print(f"all words: {len(self.words)}")
        print(f"common words: {len(self.emitted)}", end=' ')
        bits = math.log(len(self.emitted), 2) if self.emitted else 0
        print(f"entropy: {bits:.3f} bits")
        print(f"'bad' words: {len(self.bad)}")
        print(f"seen uids: {len(self.uids)}", end=' ')
        if self.uids:
            print(f"{min(self.uids)} -> {max(self.uids)}", end=' ')
        print()

    def start_reader(self):
        "Fire up the IMAP reader thread."
        if self.reader is None or not self.reader.is_alive():
            self.log.debug("starting IMAP thread.")
            self.reader = threading.Thread(target=self.read_imap,
                                            name="imap-thread",
                                            args=())
            self.reader.daemon = True
            self.reader.start()

    def get_commands(self):
        "Reader loop."
        try:
            while True:
                prompt = "? " if self.options["prompt"] else ""
                try:
                    command = input(prompt).strip()
                except EOFError:
                    break
                if not command:
                    continue
                try:
                    command, rest = command.split(None, 1)
                except ValueError:
                    rest = ""
                simple = {
                    "read": self.start_reader,
                    "stat": self.print_statistics,
                    "rebuild": self.rebuild,
                    "save": self.save_pfile,
                    "help": usage,
                    "?": usage,
                }
                with self:
                    simplefunc = simple.get(command)
                    if simplefunc is not None:
                        simplefunc()
                        continue
                    if command == "password":
                        self.generate_passwords(int(rest) if rest else 1)
                    elif command in ("exit", "quit"):
                        break
                    elif command == "bad":
                        for word in rest.split():
                            self.bad_polly(word)
                    elif command == "dict":
                        not_really_words = " ".join(self.get_not_words(rest))
                        print(textwrap.fill(not_really_words))
                    elif command == "add":
                        dictfile, nwords = rest.split()
                        nwords = int(nwords)
                        self.add_words(dictfile, nwords)
                    elif command == "good":
                        dictfile = rest
                        good = set(word.strip() for word in open(dictfile))
                        self.good_words |= good
                    elif command == "option":
                        if not rest.strip():
                            for option in sorted(self.options):
                                print(f"option {option} {self.options[option]}")
                        else:
                            option, value = rest.split()
                            if option == "verbose":
                                value = value.upper()
                                assert hasattr(logging, value)
                                self.options["verbose"] = value
                                self.log.setLevel(self.options["verbose"])
                            elif option in ("length", "maxchars", "nwords", "maxchars",
                                            "minchars", "lookback"):
                                self.options[option] = int(value)
                            elif option in ("digits", "punctuation", "upper", "hash", "prompt",
                                            "unittests"):
                                value = value.lower()
                                assert value in ("true", "false")
                                self.options[option] = value == "true"
                            elif option == "editing-mode":
                                value = value.lower()
                                assert value in ("emacs", "vi")
                                self.options[option] = value
                            elif option == "folder":
                                self.options[option] = value
                            else:
                                self.log.error("Don't know how to set option %r", option)
                    else:
                        self.log.error("Unrecognized command %r", command)
        except KeyboardInterrupt:
            pass

        self.log.info("Awk! Goodbye...")

    def generate_passwords(self, count):
        "Generate COUNT passwords."
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
        while True:
            self.read_loop()
            time.sleep(600)

    def read_loop(self):
        with self:
            options = self.options.copy()
            msg_ids = self.msg_ids.copy()
            seen_uids = self.uids.copy()

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
                self.log.error("login failed. check your credentials.")
                return
            self.log.debug("login successful.")
            info = server.select_folder(options["folder"])
            self.log.debug("select folder %r.", info)

            nmsgs = nnew = 0
            self.log.debug("look back %d days.", options["lookback"])
            start = datetime.datetime.now()-datetime.timedelta(days=options["lookback"])
            uids = server.search(["SINCE", start])
            uids = set(uids) - seen_uids
            self.log.info("%d new UIDs returned.", len(uids))
            for uid in uids:
                seen_uids.add(uid)
                try:
                    result = server.fetch([uid], [b'RFC822'])
                except imaplib.IMAP4.abort as abt:
                    self.log.error("%s uid=%s", abt, uid)
                    raise
                msg = email.message_from_bytes(result[uid][b"RFC822"])
                msg_id = msg["Message-ID"].strip()
                if msg_id in msg_ids:
                    # Already processed
                    continue
                self.log.debug("UID: %s, Message-ID: %r", uid, msg_id)
                msg_ids.add(msg_id)

                # We haven't seen this message yet. Process its text
                # (well, the first text/plain part or the plain text of
                # the first text/html part we come across).
                nmsgs += 1
                text = self.get_body(msg)
                if not text:
                    continue

                nnew += 1
                with self:
                    nwords, nhtml = self.process_text(text)
                    if nwords or nhtml:
                        self.log.debug("%d new words from %s (%d HTML tags).",
                                       nwords, msg_id, nhtml)

                if nnew % 100 == 0:
                    self.log.warning("msgs: %d new: %d", nmsgs, nnew)
                    with self:
                        self.msg_ids = msg_ids.copy()
                        self.uids = seen_uids.copy()
                elif nnew % 10 == 0:
                    self.log.info("msgs: %d new: %d", nmsgs, nnew)

            self.log.warning("Finished. msgs: %d new: %d", nmsgs, nnew)
            with self:
                self.msg_ids = msg_ids.copy()
                self.uids = seen_uids.copy()

    # get_charset and get_body are adapted from:
    #  http://ginstrom.com/scribbles/2007/11/19/parsing-multilingual-email-with-python/

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
                    payload = str(part.get_payload(decode=True), charset, "replace")
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
    if configfile is not None:
        # Fill in what wasn't given on the command line.
        config = RawConfigParser()
        config.read(configfile)
        for key in options:
            if options[key] is None:
                try:
                    value = getattr(config, GETTERS[key])("Polly", key)
                except NoOptionError:
                    pass
                else:
                    options[key] = value

        # These can legitimately be unspecified.
        if options["length"] is None:
            options["length"] = 4

        if options["nwords"] is None:
            options["nwords"] = 2048

        if options["maxchars"] is None:
            options["maxchars"] = 999

        if options["minchars"] is None:
            options["minchars"] = 3

        if options["lookback"] is None:
            options["lookback"] = 50

        if options["punctuation"] is None:
            options["punctuation"] = True

        if options["upper"] is None:
            options["upper"] = True

        if options["digits"] is None:
            options["digits"] = True

        if options["editing-mode"] is None:
            options["editing-mode"] = "emacs"

        if options["hash"] is None:
            options["hash"] = False

        if options["prompt"] is None:
            options["prompt"] = True

        if options["unittests"] is None:
            options["unittests"] = False

        if options["picklefile"] is None:
            pfile = os.path.join(os.getcwd(), "polly.pkl")
            options["picklefile"] = pfile
        options["picklefile"] = os.path.abspath(options["picklefile"])

GETTERS = {
    "server": "get",
    "user": "get",
    "password": "get",
    "prompt": "get",
    "folder": "get",
    "length": "getint",
    "lookback": "getint",
    "nwords": "getint",
    "verbose": "get",
    "digits": "getboolean",
    "punctuation": "getboolean",
    "upper": "getboolean",
    "minchars": "getint",
    "maxchars": "getint",
    "editing-mode": "get",
    "hash": "getboolean",
    "unittests": "getboolean",
    "picklefile": "get",
    }

def main(args):
    "Where it all starts."

    add_log_level("TRACE", logging.DEBUG - 5)

    options = {
        "server": None,
        "user": None,
        "password": None,
        "folder": None,
        "length": None,
        "lookback": None,
        "nwords": None,
        "verbose": None,
        "digits": None,
        "punctuation": None,
        "upper": None,
        "minchars": None,
        "maxchars": None,
        "editing-mode": None,
        "hash": None,
        "prompt": None,
        "unittests": None,
        "picklefile": None,
        }

    argstring = "s:u:p:f:c:g:HhL:n"
    # Process the command line args once to locate any config file
    opts, _args = getopt.getopt(args, argstring, ["help"])
    configfile = None
    for opt, arg in opts:
        if opt == "-c":
            configfile = arg
        elif opt in ("-h", "--help"):
            usage()
            return 0

    log_level = logging.FATAL
    read_config(configfile, options)

    generate_n = 0
    opts, _args = getopt.getopt(args, argstring, ["help"])
    for opt, arg in opts:
        # Ignore -c and -h on this pass.a
        if opt == "-u":
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
        elif opt == "-n":
            options["prompt"] = False
        elif opt == "-H":
            options["hash"] = True

    if options["verbose"] is not None:
        log_level = getattr(logging, options["verbose"].upper(), -99)
        if log_level == -99:
            raise ValueError("Invalid log level %r" % options["verbose"])

    logging.basicConfig(format=LOG_FORMAT, force=True)

    polly = Polly(options)

    # Just generate some passwords
    if generate_n:
        if options["hash"]:
            def encrypt(passwd):
                return "$dummy$" + binascii.hexlify(passwd)
        else:
            encrypt = lambda passwd: passwd
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
        polly.get_commands()
    finally:
        polly.save_pfile()

    return 0

if __name__ == "__main__":
    main(sys.argv[1:])
