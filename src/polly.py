#!/usr/bin/env python

"""polly - build a corpus from an IMAP folder and use it to generate passwords.

usage: %(PROG)s args ...

Config File Options
-------------------

The following options can be specified in the config file. Some can
also be given on the command line.

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

The following commands can be given at the interactive command prompt.

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

import argparse
import atexit
import binascii
import bz2
import configparser
import datetime
import email
from email.iterators import typed_subpart_iterator
import gzip
import hashlib
import imaplib
import logging
import math
import os
import pickle
import random
import readline
import socket
import ssl
import string
import sys
import textwrap
import threading
import time
import traceback

import imapclient

PROG = os.path.split(sys.argv[0])[1]

LOG_FORMAT = "%(asctime)-15s %(levelname)s %(message)s"

PUNCT = set(string.punctuation)
UPPER = set(string.ascii_uppercase)
LOWER = set(string.ascii_lowercase)
DIGITS = set(string.digits)

# pylint: disable=too-many-public-methods
class Polly:
    "Workhorse of the system."
    def __init__(self, options):
        self._log_fp = None
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
        # Shared between the main thread and IMAP thread so the former
        # can signal the latter to exit cleanly.
        self.exiting = threading.Event()
        self.exiting.clear()
        self.server = None
        self.nnew = 0
        self.nuids = 0
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
        if threading.current_thread() != threading.main_thread():
            self.sema.acquire()
        return self

    def __exit__(self, _type, _value, _traceback):
        if threading.current_thread() != threading.main_thread():
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
                # We always shuffle extras so that for testing we
                # exercise the RNG a consistent number of
                # times. (So he says...)
                self.rng.shuffle(extras)
                # 15% chance to insert something between letters.
                if self.rng.random() < 0.3 / length and extras:
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
        not_really_words = textwrap.fill(not_really_words).strip()
        if not_really_words:
            print(not_really_words)

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
                       if (not set(w) & upper_and_punct) and len(w) >= 4]
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
        # Skip known bad words...
        candidates = candidates - self.bad
        minchars = self.options["minchars"]
        # ... and short words
        candidates = {word for word in candidates if len(word) >= minchars}
        nwords = self.options["nwords"]
        for word in candidates:
            wset = set(word)
            if wset & LOWER != wset:
                # Only lower case ASCII - no numbers, punct, accents,
                # HTML tags ...
                continue
            self.words[word] = self.words.get(word, 0) + 1
            if (len_words := len(self.words)) < 250:
                continue
            if word not in self.emitted and self.words[word] >= 7:
                counts = sorted(self.words.values())
                if counts.index(self.words[word]) >= len_words - nwords:
                    self.emitted.add(word)
        return (len(self.emitted) - nemitted, len(html))

    def print_statistics(self, _arg):
        "Print some summary details."
        self.print_and_log("DEBUG", f"message ids: {len(self.msg_ids)}")
        self.print_and_log("DEBUG", f"all words: {len(self.words)}")
        md5 = hashlib.new("md5")
        for word in sorted(self.emitted):
            md5.update(word.encode("utf-8"))
        digest = md5.hexdigest()
        bits = math.log(len(self.emitted), 2) if self.emitted else 0
        self.print_and_log("DEBUG", f"common words: {len(self.emitted)}"
                           f" entropy: {bits * self.options['length']:.3f} bits"
                           f" hash: {digest}")
        self.print_and_log("DEBUG", f"'bad' words: {len(self.bad)}")
        if self.uids:
            self.print_and_log("DEBUG", f"seen uids: {len(self.uids)}"
                               f" {min(self.uids)} -> {max(self.uids)}")
        else:
            self.print_and_log("DEBUG", "no uids")

    def print_and_log(self, level, msg):
        "Print args and log @ level if log doesn't go to screen."
        print(msg)
        if not os.isatty(self.log_fp.fileno()):
            self.log.log(getattr(logging, level, level), msg)

    def start_reader(self, _arg):
        "Fire up the IMAP reader thread."
        if self.reader is not None and self.reader.is_alive():
            self.log.warning("IMAP thread already running.")
            return
        self.log.debug("starting IMAP thread.")
        self.reader = threading.Thread(target=self.read_imap,
                                       name="imap-thread",
                                       args=())
        self.reader.start()
        self.reader = None

    def read_and_exit(self, _arg):
        "Fire up IMAP reader thread and exit."
        if self.reader is not None and self.reader.is_alive():
            self.log.error("IMAP thread is already running.")
            return
        # Just one pass...
        self.read_loop()


    def get_commands(self, commands=""):
        "Command loop. Execute argument commands first."
        # Add new commands here as a method which takes a single argument.
        cmdmap = {
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
            "once": self.read_and_exit,
        }
        try:
            while True:
                if commands:
                    user_input = commands.strip()
                    commands = ""
                else:
                    prompt = "? " if (sys.stdin.isatty() and
                                      self.options["prompt"]) else ""
                    user_input = input(prompt).strip()
                if not user_input:
                    continue
                for command in user_input.split(";"):
                    command = command.strip()
                    try:
                        command, arg = command.split(None, 1)
                    except ValueError:
                        arg = ""
                    if command in ("exit", "quit"):
                        return

                    with self:
                        cmdfunc = cmdmap.get(command)
                        if cmdfunc is not None:
                            try:
                                cmdfunc(arg)
                            # pylint: disable=broad-except
                            except Exception:
                                self.log.error("cmdfunc: %s", cmdfunc)
                                self.log.error("arg: %s", arg)
                                self.log_exception(
                                    "Exception caught at main level",
                                    sys.exc_info())
                            continue
                        self.log.error("Unrecognized command %r", command)
        except (EOFError, KeyboardInterrupt):
            pass
        finally:
            self.exiting.set()
            self.log.info("Awk! Goodbye...")

    # pylint: disable=no-self-use
    def sleep(self, arg):
        "sleep for a bit - just to support testing."
        time.sleep(float(arg))

    def set_log_level(self, level):
        "log level set from config file"
        if hasattr(logging, level):
            self.options["verbose"] = level
            self.log.setLevel(self.options["verbose"])
        else:
            self.log.error("%r is not a valid log level name", level)

    def set_logfile(self, filename):
        "logfile name set from config file"
        self.options["logfile"] = filename
        self.log_fp = smart_open(self.options["logfile"], "at")
        logging.basicConfig(format=LOG_FORMAT, force=True, stream=self.log_fp)
        self.log = logging.getLogger("polly")

    def set_boolean(self, option, value):
        "set boolean config option"
        if value in ("true", "false"):
            self.options[option] = value == "true"
        else:
            self.log.error("%r is not in (true, false)", value)

    def set_edit_mode(self, mode):
        "constrain readline editing mode to emacs or vi"
        if mode in ("emacs", "vi"):
            self.options["editing-mode"] = mode
        else:
            self.log.error("%r is not in (emacs, vi)", mode)

    def process_option(self, arg):
        "Show or set options."
        if not arg.strip():
            for option in sorted(self.options):
                value = self.options[option]
                if option in ("folder", "folders"):
                    value = ",".join(value)
                self.print_and_log("DEBUG", f"option {option} {value}")
        else:
            option, value = arg.split()
            if option == "verbose":
                self.set_log_level(value.upper())
            elif option == "logfile":
                self.set_logfile(value)
            elif option in ("length", "maxchars", "nwords", "maxchars",
                            "minchars", "lookback"):
                self.options[option] = int(value)
            elif option in ("digits", "punctuation", "upper", "hash", "prompt",
                            "unittests"):
                self.set_boolean(option, value.lower())
            elif option == "editing-mode":
                self.set_edit_mode(value.lower())
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
        starts = 0
        while True:
            try:
                self.read_loop()
            # pylint: disable=broad-except
            except Exception:
                # We catch anything here because we want keep trying,
                # at least a few times.
                self.log_exception("Exception raised in IMAP reader thread.",
                                   sys.exc_info())
                # Reader thread crapped out. Maybe restart.
                if starts < 10:
                    # Hasn't failed enough. Restart.
                    starts += 1
                    self.log.warning("Reentering IMAP reader loop (#%d).",
                                     starts)
                else:
                    # Bail out. User must restart app or execute
                    # 'read' command again.
                    self.log.error("Too many IMAP reader loop errors!")
                    return
            for _ in range(30):
                if self.exiting.is_set():
                    return
                time.sleep(1)

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
                                   ssl_context=ssl_context,
                                   timeout=30.0) as self.server:
            try:
                self.server.login(options["user"], options["password"])
            except (imapclient.exceptions.IMAPClientError, socket.gaierror):
                self.log.error("login failed. check your credentials.")
                self.log.error("Exiting read loop early")
                return
            self.log.debug("login successful.")
            self.nnew = 0
            for folder in options["folder"]:
                try:
                    self.select_and_read(folder)
                except (ConnectionError, imaplib.IMAP4.error) as abt:
                    self.log.error("Server read error %s", abt)
                    self.log.error("Exiting read loop early")
                    return
            self.log.warning("Finished. All new msgs: %d", self.nnew)
        self.server = None

    def select_and_read(self, folder):
        "Check folder on server for new messages."
        with self:
            options = self.options.copy()
            msg_ids = self.msg_ids.copy()
            seen_uids = self.uids.copy()
        try:
            self.server.select_folder(folder)
            self.log.debug("select folder %r.", folder)
            self.log.debug("look back %d days.", options["lookback"])
            start = (datetime.datetime.now() -
                     datetime.timedelta(days=options["lookback"]))
            uids = self.server.search([b"SINCE", start.date()])
            uids = sorted((folder, uid) for uid in uids)
            uids = list(set(uids) - seen_uids)
            self.nuids = len(uids)
            self.log.warning("%s: %d new UIDs returned.", folder, self.nuids)
            while uids and not self.exiting.is_set():
                (chunk, uids) = (uids[:100], uids[100:])
                chunk = [uid for (_folder, uid) in chunk]
                (retry, seen) = self.process_chunk(folder, chunk, msg_ids)
                seen_uids |= seen
                # In case any UIDs failed, retry them once. In my
                # limited experience, errors seem to be transient.
                if retry:
                    self.log.warning("Failed UIDs on first try: %s", retry)
                    (retry, seen) = self.process_chunk(folder, retry, msg_ids)
                    seen_uids |= seen
                    if retry:
                        self.log.error("Failed UIDs on second try: %s", retry)
            self.log.warning("%s new msgs: %d", folder, self.nnew)
        finally:
            with self:
                self.msg_ids |= msg_ids
                self.uids |= seen_uids

    def process_chunk(self, folder, chunk, msg_ids):
        "Fetch body/envelope info for a group of uids."
        retry = set()
        seen_uids = set()
        result = self.server.fetch(chunk, [b'BODY.PEEK[TEXT]', b'ENVELOPE'])
        self.log.debug("Process folder %s: %s ... %s", folder, chunk[0],
                       chunk[-1])
        for uid in chunk:
            seen_uids.add((folder, uid))
            if uid not in result:
                self.log.error("UID %s in folder %s not returned from fetch.",
                               uid, folder)
                retry.add(uid)
                continue
            try:
                env = result[uid][b"ENVELOPE"]
            except KeyError:
                self.log_exception(
                    f"KeyError for {folder}:{uid} {result[uid]}"
                    " (missing envelope)",
                    sys.exc_info())
                retry.add(uid)
                continue
            try:
                body = result[uid][b"BODY[TEXT]"]
            except KeyError:
                self.log_exception(
                    f"KeyError for {folder}:{uid}/{env.message_id}"
                    " {result[uid]} (missing body text)",
                    sys.exc_info())
                retry.add(uid)
                continue
            self.process_one_message(uid, body, env, msg_ids)
            if self.nnew % 100 == 0:
                self.log.warning("%s new msgs: %d/%d",
                                 folder, self.nnew, self.nuids)
                with self:
                    self.msg_ids |= msg_ids
                    self.uids |= seen_uids
            elif self.nnew % 10 == 0:
                self.log.info("%s new msgs: %d", folder, self.nnew)
        return (sorted(retry), seen_uids)

    def process_one_message(self, uid, body, envelope, msg_ids):
        "Handle one message"
        msg = email.message_from_bytes(body)
        self.log.trace("%s", envelope)
        msg_id = envelope.message_id
        if msg_id in msg_ids:
            # Already processed
            return
        self.log.debug("UID: %s, Date: %s, Message-ID: %r",
                       uid, envelope.date, msg_id)
        msg_ids.add(msg_id)

        # We haven't seen this message yet. Process its text
        # (well, the first text/plain part or the plain text of
        # the first text/html part we come across).
        text = self.get_body(msg)
        if not text:
            return

        with self:
            nwords, nhtml = self.consider_words(set(text.split()))
            if nwords or nhtml:
                self.log.debug("%d new words from %s (%d HTML tags).",
                               nwords, msg_id, nhtml)

        self.nnew += 1

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

    def log_exception(self, message, exc_info):
        "Log exception with traceback at error level"
        exc = "".join(traceback.format_exception(*exc_info)).split("\n")
        for msg in [message] + exc:
            self.log.error(msg)

    def print_passwords(self, ntimes):
        "Simplest use. Generate ntimes passwords and exit."
        try:
            for _ in range(ntimes):
                pwd = self.get_password()
                print(pwd)
        # pylint: disable=broad-except
        except Exception:
            return 1
        return 0

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

def setup_line_editing(rcfile, mode):
    "Readline setup."
    readline.parse_and_bind('tab: complete')
    readline.parse_and_bind('set editing-mode %s' % mode)
    histfile = os.path.expanduser(rcfile)
    try:
        readline.read_history_file(histfile)
    except IOError:
        pass
    atexit.register(readline.write_history_file, histfile)

GETTERS = {
    "commands": "get",
    "configfile": "get",
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
    "npwds": "getint",
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

def process_options(options):
    "Parse command line."
    parser = argparse.ArgumentParser(description='Generate XKCD 936-ish passwords'
                                     ' or input dictionary from IMAP folder(s)')
    parser.add_argument('-c', '--config', dest='configfile', help='define config file')
    parser.add_argument('-u', '--user', dest='user', help='IMAP user name')
    parser.add_argument('-p', '--pass', '--pwd', dest='password', help='IMAP password')
    parser.add_argument('-f', '--folder', dest='folders', action='append',
                        help='IMAP folders')
    parser.add_argument('-s', '--server', dest='server', help='IMAP server')
    parser.add_argument('-g', '--generate', dest='npwds', type=int, default=0,
                        help='Number of passwords to generate')
    parser.add_argument('-L', '--level', dest='verbose', default="FATAL",
                        help='Log level')
    parser.add_argument('-l', '--logfile', dest='logfile', default="/dev/stderr",
                        help='Logfile name')
    parser.add_argument('-n', '--prompt', dest='prompt', default=True,
                        action='store_false', help='Suppress display prompt')
    parser.add_argument('-H', '--hash', dest='hash', default=False, action='store_true',
                        help='Use constant hash seed (testing only)')
    parser.add_argument('-C', '--commands', dest='commands', default="",
                        help="Commands to execute instead of generating prompt")
    args = parser.parse_args()
    for key in options:
        if hasattr(args, key):
            options[key] = getattr(args, key)
    if options["configfile"] is not None:
        read_config(options["configfile"], options)

def main():
    "Where it all starts."

    # More verbose than DEBUG...
    add_log_level("TRACE", logging.DEBUG - 5)

    # Options related to the IMAP connection have no default, hence
    # None.  They must be specified on the command line or in the
    # config file if you plan to chat with the server.
    options = {
        "commands": "",
        "configfile": None,
        "digits": True,
        "editing-mode": "emacs",
        "folder": None,
        "hash": False,
        "length": 4,
        "logfile": "/dev/stderr",
        "lookback": 50,
        "maxchars": 999,
        "minchars": 3,
        "npwds": 0,
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

    process_options(options)

    log = smart_open(options["logfile"], "at")
    logging.basicConfig(format=LOG_FORMAT, force=True, stream=log)

    polly = Polly(options)
    polly.log_fp = log

    # Just generate some passwords
    if options["npwds"] > 0:
        return polly.print_passwords(options["npwds"])

    setup_line_editing("~/.polly.rc", options["editing-mode"])

    try:
        polly.get_commands(options["commands"])
    finally:
        polly.save_pfile(None)

    return 0

if __name__ == "__main__":
    sys.exit(main())
