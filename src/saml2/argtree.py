__author__ = "roland"


def find_paths(cls, arg, path=None, seen=None, res=None, lev=0):
    """Discover attribute paths defined on a SAML class hierarchy.

    :param cls: SAML class whose ``c_children`` and ``c_attributes`` metadata
        should be traversed.
    :param arg: Attribute or child name that should be located.
    :param path: Accumulated path segments while descending the tree.
    :param seen: Sequence of classes that have already been inspected to avoid
        infinite recursion.
    :param res: Mutable list that will be populated with discovered paths.
    :param lev: Current recursion depth; used to initialise ``res`` on the
        first invocation.
    :return: A list of matching paths when called from the top-level. Recursive
        invocations return ``None`` to keep the traversal lightweight.
    """
    if lev == 0 and res is None:
        res = []

    if path is None:
        path = []

    if seen is None:
        seen = [cls]
    else:
        if cls in seen:
            return None

        seen.append(cls)

    for cn, c in cls.c_children.values():
        _path = path + [cn]
        if cn == arg:
            if res is not None:
                res.append(_path)
        else:
            if isinstance(c, list):
                _c = c[0]
            else:
                _c = c

            find_paths(_c, arg, _path, seen, res)

    for an, typ, mult in cls.c_attributes.values():
        if an == arg:
            if res is not None:
                res.append(path + [an])

    if lev == 0:
        return res


def set_arg(cls, arg, value):
    """Build dictionaries that assign ``value`` to every matching attribute.

    :param cls: SAML class whose metadata will be inspected.
    :param arg: Attribute or child element name that should be set.
    :param value: Value to assign at the terminal path element.
    :return: A list containing one dictionary per matching path. Each
        dictionary describes how to reach the attribute from the root object.
    """
    res = []
    for path in find_paths(cls, arg):
        x = y = {}
        for arc in path[:-1]:
            y[arc] = {}
            y = y[arc]
        y[path[-1]] = value
        res.append(x)

    return res


def add_path(tdict, path):
    """Create or extend an argument tree ``tdict`` from ``path``.

    :param tdict: A dictionary representing an argument tree.
    :param path: A path list.
    :return: A dictionary representing the updated argument tree.

    Convert a list of items in a ``path`` into a nested dict, where the
    second to last item becomes the key for the final item. The remaining
    items in the path become keys in the nested dict around that final pair
    of items.

    For example, for input values of::

        tdict = {}
        path = ['assertion', 'subject', 'subject_confirmation',
                'method', 'urn:oasis:names:tc:SAML:2.0:cm:bearer']

    returns the output::

        {'assertion': {'subject': {'subject_confirmation':
                      {'method': 'urn:oasis:names:tc:SAML:2.0:cm:bearer'}}}}

    Another example, this time with a non-empty ``tdict`` input::

        tdict = {'method': 'urn:oasis:names:tc:SAML:2.0:cm:bearer'}
        path = ['subject_confirmation_data', 'in_response_to', '_012345']

    returns the output::

        {'subject_confirmation_data': {'in_response_to': '_012345'},
         'method': 'urn:oasis:names:tc:SAML:2.0:cm:bearer'}
    """
    t = tdict
    for step in path[:-2]:
        try:
            t = t[step]
        except KeyError:
            t[step] = {}
            t = t[step]
    t[path[-2]] = path[-1]

    return tdict


def is_set(tdict, path):
    """Determine whether a path inside an argument tree has a value.

    :param tdict: A dictionary representing an argument tree.
    :param path: A path list.
    :return: ``True`` if the value is set, otherwise ``False``.
    """
    t = tdict
    for step in path:
        try:
            t = t[step]
        except KeyError:
            return False

    if t is not None:
        return True

    return False


def get_attr(tdict, path):
    """Fetch the value located at ``path`` inside ``tdict``.

    :param tdict: A dictionary representing an argument tree.
    :param path: A path list describing the nested traversal.
    :return: The value stored at the end of ``path``.
    """
    t = tdict
    for step in path:
        t = t[step]

    return t
