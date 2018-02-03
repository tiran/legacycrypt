"""Wrapper to the POSIX crypt library call and associated functionality."""

import ctypes as _ctypes
import string as _string
from random import SystemRandom as _SystemRandom
from collections import namedtuple as _namedtuple

__version__ = "0.2.3.7.0b1"

_saltchars = _string.ascii_letters + _string.digits + './'
_sr = _SystemRandom()


class _crypt_data(_ctypes.Structure):
    __slots__ = ()
    _fields_ = [
        ("keysched", _ctypes.c_char * 16 * 8),
        ("sb0", _ctypes.c_char * 32768),
        ("sb1", _ctypes.c_char * 32768),
        ("sb2", _ctypes.c_char * 32768),
        ("sb3", _ctypes.c_char * 32768),
        ("crypt_3_buf", _ctypes.c_char * 14),
        ("current_salt", _ctypes.c_char * 2),
        ("current_saltbits", _ctypes.c_int64),
        ("direction", _ctypes.c_int32),
        ("initialized", _ctypes.c_int32),
    ]


try:
    _LIBCRYPT = _ctypes.CDLL('libxcrypt.so')
except OSError:
    try:
        _LIBCRYPT = _ctypes.CDLL('libcrypt.so')
    except OSError:
        raise ImportError("libcrypt / libxcrypt missing")


class c_text_p(_ctypes.c_char_p):
    @classmethod
    def from_param(cls, value):
        if value is None:
            return None
        if isinstance(value, str):
            return value.encode('utf-8')
        elif isinstance(value, bytes):
            return value
        else:
            raise TypeError(value)


if hasattr(_LIBCRYPT, "crypt_r"):
    _crypt_r = _LIBCRYPT.crypt_r
    _crypt_r.argtypes = (
        c_text_p,
        c_text_p,
        _ctypes.POINTER(_crypt_data)
    )
    _crypt_r.restype = _ctypes.c_char_p

    def _crypt(key, salt):
        data = _crypt_data()
        return _crypt_r(key, salt, data)
else:
    _crypt = _LIBCRYPT.crypt
    _crypt.argtypes = (
        c_text_p,
        c_text_p,
    )
    _crypt.restype = _ctypes.c_char_p


class _Method(_namedtuple('_Method', 'name ident salt_chars total_size')):

    """Class representing a salt method per the Modular Crypt Format or the
    legacy 2-character crypt method."""

    def __repr__(self):
        return '<crypt.METHOD_{}>'.format(self.name)


def mksalt(method=None, *, rounds=None):
    """Generate a salt for the specified method.

    If not specified, the strongest available method will be used.

    """
    if method is None:
        method = methods[0]
    if rounds is not None and not isinstance(rounds, int):
        raise TypeError(f'{rounds.__class__.__name__} object cannot be '
                        f'interpreted as an integer')
    if not method.ident:  # traditional
        s = ''
    else:  # modular
        s = f'${method.ident}$'

    if method.ident and method.ident[0] == '2':  # Blowfish variants
        if rounds is None:
            log_rounds = 12
        else:
            log_rounds = int.bit_length(rounds-1)
            if rounds != 1 << log_rounds:
                raise ValueError('rounds must be a power of 2')
            if not 4 <= log_rounds <= 31:
                raise ValueError('rounds out of the range 2**4 to 2**31')
        s += f'{log_rounds:02d}$'
    elif method.ident in ('5', '6'):  # SHA-2
        if rounds is not None:
            if not 1000 <= rounds <= 999_999_999:
                raise ValueError('rounds out of the range 1000 to 999_999_999')
            s += f'rounds={rounds}$'
    elif rounds is not None:
        raise ValueError(f"{method} doesn't support the rounds argument")

    s += ''.join(_sr.choice(_saltchars) for char in range(method.salt_chars))
    return s


def crypt(word, salt=None):
    """Return a string representing the one-way hash of a password, with a salt
    prepended.

    If ``salt`` is not specified or is ``None``, the strongest
    available method will be selected and a salt generated.  Otherwise,
    ``salt`` may be one of the ``crypt.METHOD_*`` values, or a string as
    returned by ``crypt.mksalt()``.

    """
    if salt is None or isinstance(salt, _Method):
        salt = mksalt(salt)
    return _crypt(word, salt)


#  available salting/crypto methods
methods = []

def _add_method(name, *args, rounds=None):
    method = _Method(name, *args)
    globals()['METHOD_' + name] = method
    salt = mksalt(method, rounds=rounds)
    result = crypt('', salt)
    if result and len(result) == method.total_size:
        methods.append(method)
        return True
    return False

_add_method('SHA512', '6', 16, 106)
_add_method('SHA256', '5', 16, 63)

# Choose the strongest supported version of Blowfish hashing.
# Early versions have flaws.  Version 'a' fixes flaws of
# the initial implementation, 'b' fixes flaws of 'a'.
# 'y' is the same as 'b', for compatibility
# with openwall crypt_blowfish.
for _v in 'b', 'y', 'a', '':
    if _add_method('BLOWFISH', '2' + _v, 22, 59 + len(_v), rounds=1<<4):
        break

_add_method('MD5', '1', 8, 34)
_add_method('CRYPT', None, 2, 13)

del _v, _add_method
