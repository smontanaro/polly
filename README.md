# Polly

Note: I developed this for my personal use. Do not use it unless you
understand the ramifications of using security software which almost
certainly has bugs which black hats could exploit.

Build a corpus of common words from messages in an IMAP folder then
use that to generate XKCD936-style passwords.

Run "python polly.py -h" to get a brief description of how to run the
program. See polly.cfg.sample for a sample config file.  It's particularly
easy to connect to a Gmail server. Generate an application password to use
in the password field, then create a filter to funnel common *public*
mailing list mail into a "polly" label, then set the folder option to polly.
Once you have the config file set up, just run it like so:

python polly.py -c polly.cfg

Enter "help" at the "?" prompt to get a sumary of commands you can run at
the prompt.

## Motivation

I got the idea from a [post by Chris Angelico to
comp.lang.python](https://mail.python.org/pipermail/python-list/2014-August/677475.html).
In Chris's game, Polly is a parrot who listens to the chatter of D&D players
and spits out passwords when asked.  I thought it was an excellent idea, but
as I don't play Dungeons & Dragons, I needed another way to build a
dictionary of common words. It occurred to me that searching messages posted
to public mailing lists from an IMAP server for commonly used words might
work. I'm a Gmail user, so it was easy to create a new filter which labeled
messages sent to a number of public mailing lists and Internet forums as
"polly".  Instant corpus!  The polly program is pointed at the polly
"folder" on my Gmail account and collects common words to use as the basis
of a simple random XKCD 936 password generator.

Is this a new idea? No. It is mostly a programming exercise.  The only thing
which might be considered unusual is the ability to choose the input set
from which the dictionary is constructed. In my case, for example, I created
a new label, polly, in my Gmail account. Any messages received from a number
of public mailing lists and Internet forums related to Python, cycling and
swimming are tagged with that label.  In that sense, the dictionary from
which words are chosen is probably unique, containing words which are
familiar to me, but unlikely to be found in other similar word lists like
codepoints and chainstay.  Beyond that, it's probably not too different from
other systems like [Diceware](http://world.std.com/~reinhold/diceware.html),
though slightly more automated.

## Constraints

* Minimum word length is four letters.

* Words will not be selected if they contain any character which is not
  an ASCII lower case letter.

* Processing the mail is dumb. It just tries to process "words" in the text
  portions of each message it downloads.

* The specified IMAP server is not queried by default. Once you have
  generated a corpus, you can just use it to generate passwords. Execute
  the "read" command to instruct polly to process emails from the IMAP
  server.

## Caveats

There are a number of caveats to this sort of program:

* The XKCD 936 password scheme needs a large enough corpus to choose
  from.  If your corpus is too small, the amount of entropy available
  in the suggested passwords will be small. This URL might be worth
  reading: http://security.stackexchange.com/questions/62832

* I specifically set up my IMAP folder to only contain words which
  appear on public mailing lists to which I subscribe. While adding
  other sources of words is probably okay, perhaps you should think
  twice before adding private mail to your polly folder. Still, if you
  included all your email, the risk of exposing private information is
  low, as all suggestions are generated by you, and capitalized words
  or words containing punctuation or numbers are avoided.

* Polly is probably not going to be all that helpful on systems which
  truncate passwords past a certain limit. Login passwords on many Unix
  systems come to mind. While it appears that modern systems are catching
  up, you might still find your system uses DES encryption, limiting you to
  just eight characters: http://stackoverflow.com/questions/2179649

* I'm just scratching an itch here. You're welcome to do what you want
  with polly, even suggest enhancements. Just don't expect any formal
  support. (Fork away all you Github aficionados!)

* I allow you to cheat a little. If you're having trouble generating a
  large enough corpus or simply don't want to go the IMAP route, you
  can use the add command to tell polly to select a number of words at
  random from the given file. As the typical Unix words file contains
  many not-so-common words, I included a common-words file you can use
  for this purpose. The In fact, if you don't actually want to go to
  the trouble of setting up the IMAP thing, just execute "add
  common-words 2048". The common-words file contains a little more
  than 4200 words.

* I have never before tried to communicate with an IMAP server. It
  still seems pretty complicated to me. I am probably doing things
  wrong, certainly inefficiently.

## Commands

* add dictfile n - add n random words from dictfile

* bad word ...   - mark one or more words as bad

* dict dictfile  - report words not present in dictfile

* exit           - quit the program

* help or ?      - print this help

* password [n]   - generate n passwords (default 1)

* read           - read messages from the IMAP server in a second thread

* rebuild        - rebuild the 'good' words list

* save           - write the pickle save file and bad words file

* stat           - print some simple statistics about the collected words

* verbose        - toggle verbose flag

Readline support is enabled. The default editing mode is emacs. You can set
the edit-mode option in the config file to select vi.
