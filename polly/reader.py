"Reusable IMAP reader"

from abc import abstractmethod
import bz2
import datetime
import gzip
import imaplib
import logging
import os
import socket
import ssl
import sys
import threading
import traceback

import imapclient


LOG_FORMAT = "%(asctime)-15s %(levelname)s %(message)s"


class Reader:
    """Do the heavy lifting of IMAP server reading

    Should be reusable by other applications needing server access
    """

    def __init__(self, options):
        self.options = options
        self.msg_ids = set()
        self.uids = set()
        self.reader = None
        self._log_fp = None
        self.server = None
        self.nnew = 0
        self.nuids = 0
        self.log = logging.getLogger("imapclient")
        self.log.setLevel(options["verbose"])
        # Workers will acquire/release Polly to operate on internal
        # data. See __enter__ and __exit__.
        self.sema = threading.Semaphore()
        # Shared between the main thread and IMAP thread so the former
        # can signal the latter to exit cleanly.
        self.exiting = threading.Event()
        self.exiting.clear()

    def reader_is_running(self):
        return self.reader is not None and self.reader.is_alive()

    def read_and_exit(self, _arg):
        "Fire up IMAP reader thread and exit."
        if self.reader_is_running():
            self.log.error("IMAP thread is already running.")
            return
        # Just one pass...
        self.read_loop()


    def start(self):
        if self.reader is None:
            self.reader = threading.Thread(target=self.read_imap,
                name="imap-thread",
                args=())
            self.reader.start()
            self.reader = None

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
            self.log.info("login successful.")
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

    def set_logfile(self, filename):
        "logfile name set from config file"
        self.options["logfile"] = os.path.expanduser(filename)
        self.log_fp = smart_open(self.options["logfile"], "at")
        logging.basicConfig(format=LOG_FORMAT, force=True, stream=self.log_fp)
        self.log = logging.getLogger("polly")

    def log_exception(self, message, exc_info):
        "Log exception with traceback at error level"
        exc = "".join(traceback.format_exception(*exc_info)).split("\n")
        for msg in [message] + exc:
            self.log.error(msg)

    def set_log_level(self, level):
        "log level set from config file"
        if hasattr(logging, level):
            self.options["verbose"] = level
            self.log.setLevel(self.options["verbose"])
        else:
            self.log.error("%r is not a valid log level name", level)

    @property
    def log_fp(self):
        "property to get/set logfile and close when necessary."
        return self._log_fp
    @log_fp.setter
    def log_fp(self, log_fp):
        if self._log_fp is not None and not self._log_fp.closed:
            self._log_fp.close()
        self._log_fp = log_fp

    @abstractmethod
    def process_one_message(self, uid, body, envelope, msg_ids):
        "Process a single mail message however the client wants."

    def __enter__(self):
        if threading.current_thread() != threading.main_thread():
            self.sema.acquire()
        return self

    def __exit__(self, _type, _value, _traceback):
        if threading.current_thread() != threading.main_thread():
            self.sema.release()

def smart_open(filename, mode="r", encoding="utf-8"):
    "use file extension to decide how to open filename"
    if "b" in mode:
        encoding = None
    if filename.endswith(".gz"):
        return gzip.open(filename, mode, encoding=encoding)
    if filename.endswith(".bz2"):
        return bz2.open(filename, mode, encoding=encoding)
    return open(filename, mode, encoding=encoding)
