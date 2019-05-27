"""Wrapper to the POSIX crypt library call and associated functionality."""

import ctypes as _ctypes
from ctypes.util import find_library as _find_library
import string as _string
from random import SystemRandom as _SystemRandom
from collections import namedtuple as _namedtuple

__version__ = "0.3"
__py_version__ = "3.7.3"


#
# ctypes replacement for _crypt
#

class _crypt_data_libcrypt(_ctypes.Structure):
    """struct crypt_data from glibc's crypt.h

    struct crypt_data
    {
        char keysched[16 * 8];
        char sb0[32768];
        char sb1[32768];
        char sb2[32768];
        char sb3[32768];
        /* end-of-aligment-critical-data */
        char crypt_3_buf[14];
        char current_salt[2];
        long int current_saltbits;
        int  direction, initialized;
    };
    """
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


class _crypt_data_libxcrypt(_ctypes.Structure):
    """struct crypt_data from libxcrypt's crypt.h

    #define CRYPT_OUTPUT_SIZE 384
    #define CRYPT_MAX_PASSPHRASE_SIZE 512
    #define CRYPT_DATA_RESERVED_SIZE 767
    #define CRYPT_DATA_INTERNAL_SIZE 30720

    struct crypt_data
    {
        char output[CRYPT_OUTPUT_SIZE];
        char setting[CRYPT_OUTPUT_SIZE];
        char input[CRYPT_MAX_PASSPHRASE_SIZE];
        char reserved[CRYPT_DATA_RESERVED_SIZE];
        char initialized;
        char internal[CRYPT_DATA_INTERNAL_SIZE];
    };
    """
    __slots__ = ()
    CRYPT_OUTPUT_SIZE = 384
    CRYPT_MAX_PASSPHRASE_SIZE = 512
    CRYPT_DATA_RESERVED_SIZE = 767
    CRYPT_DATA_INTERNAL_SIZE = 30720
    _fields_ = [
        ("output", _ctypes.c_char * CRYPT_OUTPUT_SIZE),
        ("setting", _ctypes.c_char * CRYPT_OUTPUT_SIZE),
        ("input", _ctypes.c_char * CRYPT_MAX_PASSPHRASE_SIZE),
        ("reserved", _ctypes.c_char * CRYPT_DATA_RESERVED_SIZE),
        ("initialized", _ctypes.c_char),
        ("internal", _ctypes.c_char * CRYPT_DATA_INTERNAL_SIZE),
    ]


try:
    # prefer libxcrypt
    _libname = _find_library('xcrypt')
    if _libname is not None:
        _crypt_data = _crypt_data_libxcrypt
    else:
        # fallback to libcrypt
        _libname = _find_library('crypt')
        if _libname is not None:
            _crypt_data = _crypt_data_libcrypt
    if _libname is not None:
        _libcrypt = _ctypes.CDLL(_libname)
    else:
        raise OSError
except OSError:
    raise ImportError("libcrypt / libxcrypt missing") from None


_crypt_r_func = _crypt_func = None

if hasattr(_libcrypt, "crypt_r"):
    _crypt_r_func = _libcrypt.crypt_r
    _crypt_r_func.argtypes = (
        _ctypes.c_char_p,
        _ctypes.c_char_p,
        _ctypes.POINTER(_crypt_data)
    )
    _crypt_r_func.restype = _ctypes.c_char_p
else:
    _crypt_func = _libcrypt.crypt
    _crypt_func.argtypes = (
        _ctypes.c_char_p,
        _ctypes.c_char_p,
    )
    _crypt_func.restype = _ctypes.c_char_p


def _crypt_crypt(word, salt):
    """Hash a *word* with the given *salt* and return the hashed password.

    [clinic input]
        crypt.crypt

        word: str
        salt: str
        /

    *word* will usually be a user's password.  *salt* (either a random 2 or 16
    character string, possibly prefixed with $digit$ to indicate the method)
    will be used to perturb the encryption algorithm and produce distinct
    results for a given *word*.

    returns Py_BuildValue("s", crypt_result)
    """
    if isinstance(word, str):
        word = word.encode('utf-8')
    else:
        raise TypeError(
            f"crypt() argument 1 must be str, not {word.__class__.__name__}"
        )
    if isinstance(salt, str):
        salt = salt.encode('utf-8')
    else:
        raise TypeError(
            f"crypt() argument 2 must be str, not {salt.__class__.__name__}"
        )

    if _crypt_r_func is not None:
        data = _crypt_data()
        crypt_result = _crypt_r_func(word, salt, data)
        # poor man's memory wiping
        _ctypes.memset(_ctypes.byref(data), 0, _ctypes.sizeof(data))
        del data
    else:
        crypt_result = _crypt_func(word, salt)

    return crypt_result.decode('utf-8') if crypt_result else None


#
# original crypt module
#

_saltchars = _string.ascii_letters + _string.digits + './'
_sr = _SystemRandom()


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
            if not 1000 <= rounds <= 999999999:
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
    return _crypt_crypt(word, salt)


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
