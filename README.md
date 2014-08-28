Polly
=====

Build a corpus of common words from message in an IMAP folder then generate
XKCD 936 passwords.

Polly is based on similar functionality Chris Angelico created for a D&D
game server:

https://mail.python.org/pipermail/python-list/2014-August/677475.html

I don't play Dungeons & Dragons, so I needed another way to build a
dictionary. It occurred to me that selecting various messages from a large
body of messages on an IMAP server might work. I'm a Gmail user, so it was
easy to create a filter which labeled messages sent to a number of public
mailing lists and Internet forums as "polly", then point a program at that
"folder" and collect common words to use as the basis of a simple random
XKCD 936 password generator.

