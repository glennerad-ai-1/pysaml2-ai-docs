# An eduPersonTargetedID comprises
# the entity name of the identity provider, the entity name of the service
# provider, and a opaque string value.
# These strings are separated by "!" symbols. This form is advocated by
# Internet2 and may overtake the other form in due course.

import hashlib
import logging
import shelve


logger = logging.getLogger(__name__)


class Eptid:
    """In-memory storage for eduPersonTargetedID references."""

    def __init__(self, secret):
        """Initialise the identifier store.

        Args:
            secret: Shared secret used when hashing identifiers.
        """
        self._db = {}
        self.secret = secret

    def make(self, idp, sp, args):
        """Produce an eduPersonTargetedID value.

        Args:
            idp: Entity identifier of the identity provider.
            sp: Entity identifier of the service provider.
            args: Tuple of stable identifiers for the subject.

        Returns:
            str: A ``!`` delimited targeted identifier.
        """
        md5 = hashlib.md5()
        for arg in args:
            md5.update(arg.encode("utf-8"))
        if isinstance(sp, bytes):
            md5.update(sp)
        else:
            md5.update(sp.encode("utf-8"))
        if isinstance(self.secret, bytes):
            md5.update(self.secret)
        else:
            md5.update(self.secret.encode("utf-8"))
        md5.digest()
        hashval = md5.hexdigest()
        if isinstance(hashval, bytes):
            hashval = hashval.decode("ascii")
        return "!".join([idp, sp, hashval])

    def __getitem__(self, key):
        """Retrieve a stored targeted identifier.

        Args:
            key: Key derived from the service provider and subject identifier.

        Returns:
            str: Persisted targeted identifier.
        """
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        return self._db[key]

    def __setitem__(self, key, value):
        """Store a targeted identifier in the internal mapping.

        Args:
            key: Dictionary key derived from the subject identifier.
            value: Targeted identifier to persist.
        """
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        self._db[key] = value

    def get(self, idp, sp, *args):
        """Return a deterministic targeted identifier.

        Args:
            idp: Entity identifier for the issuing identity provider.
            sp: Entity identifier for the relying service provider.
            *args: Stable subject identifiers such as internal IDs.

        Returns:
            str: Cached or newly generated targeted identifier.
        """
        # key is a combination of sp_entity_id and object id
        key = ("__".join([sp, args[0]])).encode("utf-8")
        try:
            return self[key]
        except KeyError:
            val = self.make(idp, sp, args)
            self[key] = val
            return val

    def close(self):
        """Clean up resources used by the store."""
        pass


class EptidShelve(Eptid):
    """Shelve-backed persistent targeted identifier store."""

    def __init__(self, secret, filename):
        """Initialise a shelve database for persistent identifiers.

        Args:
            secret: Shared secret used for deterministic hashing.
            filename: Base file name for the shelve database.
        """
        Eptid.__init__(self, secret)
        if filename.endswith(".db"):
            filename = filename.rsplit(".db", 1)[0]
        self._db = shelve.open(filename, writeback=True, protocol=2)

    def close(self):
        """Flush and close the shelve backing store."""
        self._db.close()
