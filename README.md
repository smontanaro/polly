# Polly

**Note: I developed this for my personal use. Do not use it unless you
understand the ramifications of using security software which almost
certainly has bugs which black hats could exploit.**

Build a corpus of common words from messages in an IMAP folder then
use that to generate [XKCD936-style passwords](https://xkcd.com/936/).

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
comp.lang.python](https://mail.python.org/pipermail/python-list/2014-August/827854.html).
In Chris's game, Polly is a parrot who listens to the chatter of D&D players
and spits out passwords when asked.  I thought it was an excellent idea, but
as I don't play Dungeons & Dragons, I needed another way to build a
dictionary of common words. It occurred to me that searching messages posted
to public mailing lists from an IMAP server for commonly used words might
work. I'm a Gmail user, so it was easy to create a new filter which labeled
messages sent to a number of public mailing lists and Internet forums as
"polly".  Instant corpus!  The polly program is pointed at the polly
"folder" on my Gmail account and collects common words to use as the basis
of a modified XKCD 936 passphrase generator.

Is this a new idea? No. It is mostly a programming exercise. Any
messages received from a number of public mailing lists and Internet
forums I subscribe to are tagged with that label.  In that sense, the
dictionary from which words are chosen is probably unique, containing
words which are familiar to me, but unlikely to be found in other
similar word lists like "codepoints" and "chainstay."  Beyond that,
it's probably not too different from other systems like
[Diceware](http://world.std.com/~reinhold/diceware.html), though
slightly more automated.

## Basic idea

1. Choose a set of random words (default four) from the dictionary
   (basic XKCD 936
   passphrase). For example: `correct horse battery staple`.
2. Optionally separate the words using punctuation or digits. For
   example: `correct!horse^battery5staple`.
3. Optionally upshift individual letters in the words (with low
   probability). For example: `corRect!horsE^battery5Staple`.
4. Optionally insert punctuation or digits between letters (with
   even lower probability). For example: `corRec3t!horsE^bat_tery5Staple`.

The user can choose to use any or all of the above tweaks in the
config file.

## Constraints

* Minimum word length is configurable, but defaults to four letters.

* Words will not be selected if they contain any character which is not
  an ASCII lower case letter.

* Processing the mail is dumb. It just tries to process "words" in the text
  portions of each message it downloads.

* The specified IMAP server is not queried by default. Once you have
  generated a corpus, you can just use it to generate
  passwords. Execute the "read" command to instruct polly to process
  new emails from the IMAP server. It grabs the most recent 100 days
  worth of message ids, discarding any which have already been processed.

## Caveats

There are a number of caveats to this sort of program:

* The XKCD 936 password scheme needs a large enough corpus to choose
  from.  If your corpus is too small, the amount of entropy available
  in the suggested passwords will be small. This URL might be worth
  reading: http://security.stackexchange.com/questions/62832

* I specifically set up my IMAP folder to only contain words which
  appear on public mailing lists to which I subscribe. While adding
  other sources of words is probably okay, perhaps you should think
  twice before adding words from private mail to your polly
  folder. Still, if you included all your email, the risk of exposing
  private information is low, as all suggestions are generated by you,
  and capitalized words or words containing punctuation or numbers are
  avoided.

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

* I had never before tried to communicate with an IMAP server. I am
  probably doing this inefficiently, if not downright wrong.

## Commands

* add dictfile n - add n random words from dictfile

* bad word ...   - mark one or more words as bad

* dict dictfile  - report words not present in dictfile

* exit           - quit the program

* quit           - quit the program

* good dictfile  - declare the words in dictfile to be "good" when
                   executing the dict command.

* help or ?      - print this help

* option         - display all options and their current values

* option name value - set option "name" to value

* password [n]   - generate n passwords (default 1)

* read           - read messages from the IMAP server in a second thread

* rebuild        - rebuild the 'good' words list

* save           - write the pickle save file and bad words file

* stat           - print some simple statistics about the collected words

* verbose        - toggle verbose flag

Readline support is enabled. The default editing mode is emacs. You can set
the edit-mode option in the config file to select vi.

## Options

### Dictionary Construction

* server - IMAP server
* user - email address on the server
* password - password on the server
* folder - name of the folder to process
* nwords - size of dictionary

### Generating Passwords

* punctuation - whether to include punctuation in passwords (True/False)
* digits - whether to use digits in passwords (True/False)
* upper - whether to randomly upcase some letters (True/False)
* minchars - minimum word length
* maxchars - maximum word length
* length - number of words in a passphrase

## Testing

There's not much to the testing, just some test configs in tests/cfgs which
are run with a predictable "random" number generator.  For this, a special
"unittests" option is used. Don't use it for anything else, as it completely
wrecks the random number generator.

To run the tests, execute:

    bash tests/runtests.sh

The output will be compared with tests/output/expected.out.  To add new
tests, add new config files to tests/cfgs (".cfg" is the required extension)
and run the script with the --generate command line flag. The output will be
written to stdout.
