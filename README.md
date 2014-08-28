Polly
=====

Build a corpus of common words from message in an IMAP folder then generate
XKCD 936 passwords.

Polly is based on similar functionality Chris Angelico created for a D&D
game server:

https://mail.python.org/pipermail/python-list/2014-August/677475.html

In that game, Polly is a parrot who listens to the chatter and spits out
passwords when asked.  I thought it was an excellent idea, but as I don't
play Dungeons & Dragons, I needed another way to build a dictionary of
common words. It occurred to me that searching messages from an IMAP server
for commonly used words might work. I'm a Gmail user, so it was easy to
create a new filter which labeled messages sent to a number of public
mailing lists and Internet forums as "polly". Instant corpus!  The polly
program is pointed at the polly "folder" on my Gmail account and collects
common words to use as the basis of a simple random XKCD 936 password
generator.

Run "python polly.py -h" to get a brief description of how to run the
program.

