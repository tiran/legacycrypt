# Legacy crypt — Function to check Unix passwords

The legacycrypt module is a standalone version of
https://docs.python.org/3/library/crypt.html

This module implements an interface to the crypt(3) routine, which is a
one-way hash function based upon a modified DES algorithm; see the Unix man
page for further details. Possible uses include storing hashed passwords so
you can check passwords without storing the actual password, or attempting
to crack Unix passwords with a dictionary.

Notice that the behavior of this module depends on the actual
implementation of the crypt(3) routine in the running system. Therefore,
any extensions available on the current implementation will also be
available on this module.