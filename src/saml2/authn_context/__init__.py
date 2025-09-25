from saml2 import extension_elements_to_elements
from saml2.authn_context import ippword
from saml2.authn_context import mobiletwofactor
from saml2.authn_context import ppt
from saml2.authn_context import pword
from saml2.authn_context import sslcert
from saml2.saml import AuthnContext
from saml2.saml import AuthnContextClassRef
from saml2.samlp import RequestedAuthnContext


UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"

INTERNETPROTOCOLPASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword"
MOBILETWOFACTORCONTRACT = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"
PASSWORDPROTECTEDTRANSPORT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
TLSCLIENT = "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient"
TIMESYNCTOKEN = "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"

AL1 = "http://idmanagement.gov/icam/2009/12/saml_2.0_profile/assurancelevel1"
AL2 = "http://idmanagement.gov/icam/2009/12/saml_2.0_profile/assurancelevel2"
AL3 = "http://idmanagement.gov/icam/2009/12/saml_2.0_profile/assurancelevel3"
AL4 = "http://idmanagement.gov/icam/2009/12/saml_2.0_profile/assurancelevel4"

CMP_TYPE = ["exact", "minimum", "maximum", "better"]


class AuthnBroker:
    """Broker for mapping requested contexts to available IdP methods."""

    def __init__(self):
        """Initialise an empty broker."""

        self.db = {"info": {}, "key": {}}
        self.next = 0

    @staticmethod
    def exact(a, b):
        return a == b

    @staticmethod
    def minimum(a, b):
        return b >= a

    @staticmethod
    def maximum(a, b):
        return b <= a

    @staticmethod
    def better(a, b):
        return b > a

    def add(self, spec, method, level=0, authn_authority="", reference=None):
        """Register a new authentication method for a given context.

        :param spec: The advertised :class:`~saml2.saml.AuthnContext` or
            declaration describing the method.
        :param method: Identifier that the IdP uses internally when invoking
            the authenticating mechanism.
        :param level: Positive integer indicating the strength of the method;
            higher values represent a stronger assurance level.
        :param authn_authority: Optional identifier of the upstream authority
            that issues the authentication event.
        :param reference: Optional explicit reference to store the
            configuration under. A unique reference is generated automatically
            when not supplied.
        :raises Exception: If the generated or supplied reference collides with
            an existing registration.
        """

        if spec.authn_context_class_ref:
            key = spec.authn_context_class_ref.text
            _info = {"class_ref": key, "method": method, "level": level, "authn_auth": authn_authority}
        elif spec.authn_context_decl:
            key = spec.authn_context_decl.c_namespace
            _info = {"method": method, "decl": spec.authn_context_decl, "level": level, "authn_auth": authn_authority}
        else:
            raise NotImplementedError()

        self.next += 1
        _ref = reference
        if _ref is None:
            _ref = str(self.next)

        if _ref in self.db["info"]:
            raise Exception("Internal error: reference is not unique")

        self.db["info"][_ref] = _info
        try:
            self.db["key"][key].append(_ref)
        except KeyError:
            self.db["key"][key] = [_ref]

    def remove(self, spec, method=None, level=0, authn_authority=""):
        """Remove registrations that match the provided constraints.

        :param spec: The :class:`~saml2.saml.AuthnContext` describing the
            registration to remove.
        :param method: Optional identifier of the method to remove. When
            omitted, all methods for the context are considered.
        :param level: Optional assurance level that must match an existing
            registration to be removed.
        :param authn_authority: Optional identifier of the authentication
            authority to match before removal.
        """
        if spec.authn_context_class_ref:
            _cls_ref = spec.authn_context_class_ref.text
            try:
                _refs = self.db["key"][_cls_ref]
            except KeyError:
                return
            else:
                _remain = []
                for _ref in _refs:
                    item = self.db["info"][_ref]
                    if method and method != item["method"]:
                        _remain.append(_ref)
                    if level and level != item["level"]:
                        _remain.append(_ref)
                    if authn_authority and authn_authority != item["authn_authority"]:
                        _remain.append(_ref)
                if _remain:
                    self.db[_cls_ref] = _remain

    def _pick_by_class_ref(self, cls_ref, comparision_type="exact"):
        """Resolve methods for the given class reference and comparison type.

        :param cls_ref: The SAML authentication context class reference URI to
            match.
        :param comparision_type: How to compare assurance levels. One of
            ``"exact"``, ``"minimum"``, ``"maximum"`` or ``"better"``.
        :return: An ordered list of ``(method, reference)`` pairs describing
            matching registrations. Methods may be ``None`` when only a
            declaration is available.
        """
        func = getattr(self, comparision_type)
        try:
            _refs = self.db["key"][cls_ref]
        except KeyError:
            return []
        else:
            _item = self.db["info"][_refs[0]]
            _level = _item["level"]
            if comparision_type != "better":
                if _item["method"]:
                    res = [(_item["method"], _refs[0])]
                else:
                    res = []
            else:
                res = []

            for ref in _refs[1:]:
                item = self.db["info"][ref]
                res.append((item["method"], ref))
                if func(_level, item["level"]):
                    _level = item["level"]
            for ref, _dic in self.db["info"].items():
                if ref in _refs:
                    continue
                elif func(_level, _dic["level"]):
                    if _dic["method"]:
                        _val = (_dic["method"], ref)
                        if _val not in res:
                            res.append(_val)
            return res

    def pick(self, req_authn_context=None):
        """Return candidate authentication methods for a request.

        :param req_authn_context: Requested context requirements provided by
            the service provider. ``None`` defaults to the ``unspecified``
            context.
        :return: An ordered list of method references that satisfy the request
            according to the requested comparison strategy.
        """

        if req_authn_context is None:
            return self._pick_by_class_ref(UNSPECIFIED, "minimum")
        if req_authn_context.authn_context_class_ref:
            if req_authn_context.comparison:
                _cmp = req_authn_context.comparison
            else:
                _cmp = "exact"
            if _cmp == "exact":
                res = []
                for cls_ref in req_authn_context.authn_context_class_ref:
                    res += self._pick_by_class_ref(cls_ref.text, _cmp)
                return res
            else:
                return self._pick_by_class_ref(req_authn_context.authn_context_class_ref[0].text, _cmp)
        elif req_authn_context.authn_context_decl_ref:
            if req_authn_context.comparison:
                _cmp = req_authn_context.comparison
            else:
                _cmp = "exact"
            return self._pick_by_class_ref(req_authn_context.authn_context_decl_ref, _cmp)

    def match(self, requested, provided):
        """Check whether a provided context fulfils a requested context.

        :param requested: Requested authentication context identifier.
        :param provided: Authentication context identifier delivered by the IdP.
        :return: ``True`` if the provided context satisfies the request.
        """

        if requested == provided:
            return True
        else:
            return False

    def __getitem__(self, ref):
        """Retrieve the stored registration details for a reference.

        :param ref: Registration reference identifier generated by :meth:`add`.
        :return: Stored metadata describing the authentication method.
        """

        return self.db["info"][ref]

    def get_authn_by_accr(self, accr):
        """Return the first registration matching a class reference.

        :param accr: Authentication context class reference URI.
        :return: The stored registration information for the first matching
            reference.
        """

        _ids = self.db["key"][accr]
        return self[_ids[0]]


def authn_context_factory(text):
    # brute force
    for mod in [ippword, mobiletwofactor, ppt, pword, sslcert]:
        inst = mod.authentication_context_declaration_from_string(text)
        if inst:
            return inst

    return None


def authn_context_decl_from_extension_elements(extelems):
    res = extension_elements_to_elements(extelems, [ippword, mobiletwofactor, ppt, pword, sslcert])
    try:
        return res[0]
    except IndexError:
        return None


def authn_context_class_ref(ref):
    return AuthnContext(authn_context_class_ref=AuthnContextClassRef(text=ref))


def requested_authn_context(class_ref, comparison="minimum"):
    if not isinstance(class_ref, list):
        class_ref = [class_ref]
    return RequestedAuthnContext(
        authn_context_class_ref=[AuthnContextClassRef(text=i) for i in class_ref], comparison=comparison
    )
