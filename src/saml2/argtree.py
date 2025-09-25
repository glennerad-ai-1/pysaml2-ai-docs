from typing import Any


__author__ = "roland"


def find_paths(cls, arg, path=None, seen=None, res=None, lev=0):
    """Discover attribute paths defined on a SAML class hierarchy.

    Args:
        cls: SAML class whose ``c_children`` and ``c_attributes`` metadata
            should be traversed.
        arg: Attribute or child name that should be located.
        path: Accumulated path segments while descending the tree.
        seen: Sequence of classes that have already been inspected to avoid
            infinite recursion.
        res: Mutable list that will be populated with discovered paths.
        lev: Current recursion depth; used to initialise the ``res`` list on
            the first invocation.

    Returns:
        list[list[str]] | None: When ``lev`` is zero a list of matching paths is
        returned. For recursive calls, ``None`` is returned to keep the
        traversal lightweight.
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
    """Build dictionaries that assign a value to every matching attribute.

    Args:
        cls: SAML class whose metadata will be inspected.
        arg: Attribute or child element name that should be set.
        value: Value to assign at the terminal path element.

    Returns:
        list[dict[str, Any]]: One dictionary for each matching path. Each
        dictionary contains nested structures that describe how to reach the
        attribute from the root object.
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
    """Create or extend an argument tree from a flattened path.

    The utility converts a list describing a traversal into a nested
    dictionary structure. The second to last element becomes a key whose value
    is the final path element. The remaining entries in ``path`` are turned
    into intermediate dictionaries that capture the hierarchy.

    Args:
        tdict: Dictionary representing a partially built argument tree.
        path: Iterable of path components describing how to reach an attribute.

    Returns:
        dict[str, Any]: The updated argument tree.
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

    Args:
        tdict: Dictionary representing the argument tree.
        path: Iterable of path segments describing the desired value.

    Returns:
        bool: ``True`` when a non-``None`` value exists at the supplied path;
        otherwise ``False``.
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

    Args:
        tdict: Dictionary representing the argument tree.
        path: Iterable of keys describing the nested traversal.

    Returns:
        Any: Value stored at the end of ``path``.
    """
    t = tdict
    for step in path:
        t = t[step]

    return t
