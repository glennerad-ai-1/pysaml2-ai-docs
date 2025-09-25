import copy
import importlib
import logging
from logging.config import dictConfig as configure_logging_by_dict
import logging.handlers
import os
import re
import sys
from warnings import warn as _warn

from saml2 import BINDING_HTTP_ARTIFACT
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_SOAP
from saml2 import BINDING_URI
from saml2 import SAMLError
from saml2.assertion import Policy
from saml2.attribute_converter import ac_factory
from saml2.mdstore import MetadataStore
from saml2.saml import NAME_FORMAT_URI
from saml2.virtual_org import VirtualOrg


logger = logging.getLogger(__name__)

__author__ = "rolandh"


COMMON_ARGS = [
    "logging",
    "debug",
    "entityid",
    "xmlsec_binary",
    "key_file",
    "cert_file",
    "encryption_keypairs",
    "additional_cert_files",
    "metadata_key_usage",
    "secret",
    "accepted_time_diff",
    "name",
    "ca_certs",
    "description",
    "valid_for",
    "verify_ssl_cert",
    "organization",
    "contact_person",
    "name_form",
    "virtual_organization",
    "only_use_keys_in_metadata",
    "disable_ssl_certificate_validation",
    "preferred_binding",
    "session_storage",
    "assurance_certification",
    "entity_attributes",
    "entity_category",
    "entity_category_support",
    "xmlsec_path",
    "extension_schemas",
    "cert_handler_extra_class",
    "generate_cert_func",
    "generate_cert_info",
    "verify_encrypt_cert_advice",
    "verify_encrypt_cert_assertion",
    "tmp_cert_file",
    "tmp_key_file",
    "validate_certificate",
    "extensions",
    "allow_unknown_attributes",
    "crypto_backend",
    "delete_tmpfiles",
    "endpoints",
    "metadata",
    "ui_info",
    "name_id_format",
    "signing_algorithm",
    "digest_algorithm",
    "http_client_timeout",
]

SP_ARGS = [
    "required_attributes",
    "optional_attributes",
    "idp",
    "aa",
    "subject_data",
    "want_response_signed",
    "want_assertions_signed",
    "want_assertions_or_response_signed",
    "authn_requests_signed",
    "name_form",
    "discovery_response",
    "allow_unsolicited",
    "ecp",
    "name_id_policy_format",
    "name_id_format_allow_create",
    "logout_requests_signed",
    "logout_responses_signed",
    "requested_attribute_name_format",
    "hide_assertion_consumer_service",
    "force_authn",
    "sp_type",
    "sp_type_in_metadata",
    "requested_attributes",
    "requested_authn_context",
]

AA_IDP_ARGS = [
    "sign_assertion",
    "sign_response",
    "encrypt_assertion",
    "encrypted_advice_attributes",
    "encrypt_assertion_self_contained",
    "want_authn_requests_signed",
    "want_authn_requests_only_with_valid_cert",
    "provided_attributes",
    "subject_data",
    "sp",
    "scope",
    "domain",
    "name_qualifier",
    "edu_person_targeted_id",
    "error_url",
]

PDP_ARGS = ["endpoints", "name_form", "name_id_format"]

AQ_ARGS = ["endpoints"]

AA_ARGS = ["attribute", "attribute_profile"]

COMPLEX_ARGS = ["attribute_converters", "metadata", "policy"]
ALL = set(COMMON_ARGS + SP_ARGS + AA_IDP_ARGS + PDP_ARGS + COMPLEX_ARGS + AA_ARGS)

SPEC = {
    "": COMMON_ARGS + COMPLEX_ARGS,
    "sp": COMMON_ARGS + COMPLEX_ARGS + SP_ARGS,
    "idp": COMMON_ARGS + COMPLEX_ARGS + AA_IDP_ARGS,
    "aa": COMMON_ARGS + COMPLEX_ARGS + AA_IDP_ARGS + AA_ARGS,
    "pdp": COMMON_ARGS + COMPLEX_ARGS + PDP_ARGS,
    "aq": COMMON_ARGS + COMPLEX_ARGS + AQ_ARGS,
}

_RPA = [BINDING_HTTP_REDIRECT, BINDING_HTTP_POST, BINDING_HTTP_ARTIFACT]
_PRA = [BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, BINDING_HTTP_ARTIFACT]
_SRPA = [BINDING_SOAP, BINDING_HTTP_REDIRECT, BINDING_HTTP_POST, BINDING_HTTP_ARTIFACT]

PREFERRED_BINDING = {
    "single_logout_service": _SRPA,
    "manage_name_id_service": _SRPA,
    "assertion_consumer_service": _PRA,
    "single_sign_on_service": _RPA,
    "name_id_mapping_service": [BINDING_SOAP],
    "authn_query_service": [BINDING_SOAP],
    "attribute_service": [BINDING_SOAP],
    "authz_service": [BINDING_SOAP],
    "assertion_id_request_service": [BINDING_URI],
    "artifact_resolution_service": [BINDING_SOAP],
    "attribute_consuming_service": _RPA,
}


class ConfigurationError(SAMLError):
    pass


class Config:
    """Represent shared configuration for IdP, SP, AA, PDP and AQ roles."""

    def_context = ""

    def __init__(self, homedir="."):
        """Initialise the configuration with default values.

        Args:
            homedir: Base directory used for resolving relative file paths.
        """

        self.logging = None
        self._homedir = homedir
        self.entityid = None
        self.xmlsec_binary = None
        self.xmlsec_path = []
        self.debug = False
        self.key_file = None
        self.cert_file = None
        self.encryption_keypairs = None
        self.additional_cert_files = None
        self.metadata_key_usage = "both"
        self.secret = None
        self.accepted_time_diff = None
        self.name = None
        self.ca_certs = None
        self.verify_ssl_cert = False
        self.description = None
        self.valid_for = None
        self.organization = None
        self.contact_person = None
        self.name_form = None
        self.name_id_format = None
        self.name_id_policy_format = None
        self.name_id_format_allow_create = None
        self.virtual_organization = None
        self.only_use_keys_in_metadata = True
        self.logout_requests_signed = None
        self.logout_responses_signed = None
        self.disable_ssl_certificate_validation = None
        self.context = ""
        self.attribute_converters = None
        self.metadata = None
        self.policy = None
        self.serves = []
        self.vorg = {}
        self.preferred_binding = PREFERRED_BINDING
        self.domain = ""
        self.name_qualifier = ""
        self.assurance_certification = []
        self.entity_attributes = []
        self.entity_category = []
        self.entity_category_support = []
        self.crypto_backend = "xmlsec1"
        self.scope = ""
        self.allow_unknown_attributes = False
        self.extension_schema = {}
        self.cert_handler_extra_class = None
        self.verify_encrypt_cert_advice = None
        self.verify_encrypt_cert_assertion = None
        self.generate_cert_func = None
        self.generate_cert_info = None
        self.tmp_cert_file = None
        self.tmp_key_file = None
        self.validate_certificate = None
        self.extensions = {}
        self.attribute = []
        self.attribute_profile = []
        self.requested_attribute_name_format = NAME_FORMAT_URI
        self.delete_tmpfiles = True
        self.signing_algorithm = None
        self.digest_algorithm = None
        self.http_client_timeout = None

    def setattr(self, context, attr, val):
        """Set a configuration attribute for the given context.

        Args:
            context: Entity context (``""`` for common attributes).
            attr: Attribute name to assign.
            val: Value to assign.
        """

        if context == "":
            setattr(self, attr, val)
        else:
            setattr(self, f"_{context}_{attr}", val)

    def getattr(self, attr, context=None):
        """Retrieve a configuration attribute, falling back to defaults.

        Args:
            attr: Attribute name to look up.
            context: Optional entity context to read from.

        Returns:
            Any: The stored value or ``None`` when undefined.
        """

        if context is None:
            context = self.context

        if context == "":
            return getattr(self, attr, None)
        else:
            return getattr(self, f"_{context}_{attr}", None)

    def load_special(self, cnf, typ):
        """Populate role-specific configuration keys.

        Args:
            cnf: Service-specific configuration dictionary.
            typ: Entity type key such as ``"idp"`` or ``"sp"``.
        """

        for arg in SPEC[typ]:
            try:
                _val = cnf[arg]
            except KeyError:
                pass
            else:
                if _val == "true":
                    _val = True
                elif _val == "false":
                    _val = False
                self.setattr(typ, arg, _val)

        self.context = typ
        self.context = self.def_context

    def load_complex(self, cnf):
        """Process configuration blocks that require additional setup.

        Args:
            cnf: Configuration dictionary.

        Raises:
            ConfigurationError: If attribute converters are missing.
        """

        acs = ac_factory(cnf.get("attribute_map_dir"))
        if not acs:
            raise ConfigurationError("No attribute converters, something is wrong!!")
        self.setattr("", "attribute_converters", acs)

        try:
            self.setattr("", "metadata", self.load_metadata(cnf["metadata"]))
        except KeyError:
            pass

        for srv, spec in cnf.get("service", {}).items():
            policy_conf = spec.get("policy")
            self.setattr(srv, "policy", Policy(policy_conf, self.metadata))

    def load(self, cnf, metadata_construction=None):
        """Load configuration data into the instance.

        Args:
            cnf: Configuration dictionary.
            metadata_construction: Deprecated argument retained for backwards
                compatibility. Passing a value triggers a warning.

        Returns:
            Config: The populated configuration instance.
        """

        if metadata_construction is not None:
            warn_msg = (
                "The metadata_construction parameter for saml2.config.Config.load "
                "is deprecated and ignored; "
                "instead, initialize the Policy object setting the mds param."
            )
            logger.warning(warn_msg)
            _warn(warn_msg, DeprecationWarning)

        for arg in COMMON_ARGS:
            if arg == "virtual_organization":
                if "virtual_organization" in cnf:
                    for key, val in cnf["virtual_organization"].items():
                        self.vorg[key] = VirtualOrg(None, key, val)
                continue
            elif arg == "extension_schemas":
                # List of filename of modules representing the schemas
                if "extension_schemas" in cnf:
                    for mod_file in cnf["extension_schemas"]:
                        _mod = self._load(mod_file)
                        self.extension_schema[_mod.NAMESPACE] = _mod

            try:
                setattr(self, arg, cnf[arg])
            except KeyError:
                pass
            except TypeError:  # Something that can't be a string
                setattr(self, arg, cnf[arg])

        if self.logging is not None:
            configure_logging_by_dict(self.logging)

        if not self.delete_tmpfiles:
            warn_msg = (
                "Configuration option `delete_tmpfiles` is set to False; "
                "consider setting this to True to have temporary files deleted."
            )
            logger.warning(warn_msg)
            _warn(warn_msg)

        if "service" in cnf:
            for typ in ["aa", "idp", "sp", "pdp", "aq"]:
                try:
                    self.load_special(cnf["service"][typ], typ)
                    self.serves.append(typ)
                except KeyError:
                    pass

        if "extensions" in cnf:
            self.do_extensions(cnf["extensions"])

        self.load_complex(cnf)
        self.context = self.def_context

        return self

    def _load(self, fil):
        """Import a configuration module from a path or dotted name.

        Args:
            fil: Path or module name pointing to the configuration module.

        Returns:
            ModuleType: Imported module containing configuration data.
        """

        head, tail = os.path.split(fil)
        if head == "":
            if sys.path[0] != ".":
                sys.path.insert(0, ".")
        else:
            sys.path.insert(0, head)

        return importlib.import_module(tail)

    def load_file(self, config_filename, metadata_construction=None):
        """Load configuration from a Python file or module.

        Args:
            config_filename: File path or module name to import.
            metadata_construction: Deprecated argument retained for backwards
                compatibility. Passing a value triggers a warning.

        Returns:
            Config: The populated configuration instance.

        Raises:
            ConfigurationError: If the module lacks a ``CONFIG`` dictionary.
        """

        if metadata_construction is not None:
            warn_msg = (
                "The metadata_construction parameter for saml2.config.Config.load_file "
                "is deprecated and ignored; "
                "instead, initialize the Policy object setting the mds param."
            )
            logger.warning(warn_msg)
            _warn(warn_msg, DeprecationWarning)

        if config_filename.endswith(".py"):
            config_filename = config_filename[:-3]

        mod = self._load(config_filename)
        return self.load(copy.deepcopy(mod.CONFIG))

    def load_metadata(self, metadata_conf):
        """Create and populate a metadata store for the configuration.

        Args:
            metadata_conf: Metadata configuration dictionary.

        Returns:
            MetadataStore: The populated metadata store.

        Raises:
            ConfigurationError: If attribute converters are missing.
        """

        acs = self.attribute_converters
        if acs is None:
            raise ConfigurationError("Missing attribute converter specification")

        try:
            ca_certs = self.ca_certs
        except Exception:
            ca_certs = None
        try:
            disable_validation = self.disable_ssl_certificate_validation
        except Exception:
            disable_validation = False

        mds = MetadataStore(
            acs,
            self,
            ca_certs,
            disable_ssl_certificate_validation=disable_validation,
            http_client_timeout=self.http_client_timeout,
        )
        mds.imp(metadata_conf)
        return mds

    def endpoint(self, service, binding=None, context=None):
        """Return endpoints matching the requested service and binding.

        Args:
            service: Service identifier, e.g. ``"single_sign_on_service"``.
            binding: Optional SAML binding to restrict results to.
            context: Optional entity context to use when selecting endpoints.

        Returns:
            list[str] | list[tuple[str, str]]: Exact endpoint URLs when binding
            is matched, otherwise the unfiltered endpoint specifications.
        """
        spec = []
        unspec = []
        endps = self.getattr("endpoints", context)
        if endps and service in endps:
            for endpspec in endps[service]:
                try:
                    # endspec sometime is str, sometime is a tuple
                    if type(endpspec) in (tuple, list):
                        # slice prevents 3-tuple, eg: sp's assertion_consumer_service
                        endp, bind = endpspec[0:2]
                    else:
                        endp, bind = endpspec
                    if binding is None or bind == binding:
                        spec.append(endp)
                except ValueError:
                    unspec.append(endpspec)

        if spec:
            return spec
        else:
            return unspec

    def endpoint2service(self, endpoint, context=None):
        """Look up the service and binding that expose a given endpoint.

        Args:
            endpoint: Endpoint URL to inspect.
            context: Optional entity context.

        Returns:
            tuple[str | None, str | None]: The ``(service, binding)`` pair or
            ``(None, None)`` when the endpoint is not found.
        """
        endps = self.getattr("endpoints", context)

        for service, specs in endps.items():
            for endp, binding in specs:
                if endp == endpoint:
                    return service, binding

        return None, None

    def do_extensions(self, extensions):
        """Merge configured extensions into the global extensions store.

        Args:
            extensions: Mapping of extension identifier to configuration data.
        """
        for key, val in extensions.items():
            self.extensions[key] = val

    def service_per_endpoint(self, context=None):
        """Return a mapping of endpoint URLs to their service and binding.

        Args:
            context: Optional entity context.

        Returns:
            dict[str, tuple[str, str]]: Mapping of endpoint URL to
            ``(service, binding)`` tuples.
        """
        endps = self.getattr("endpoints", context)
        res = {}
        for service, specs in endps.items():
            for endp, binding in specs:
                res[endp] = (service, binding)
        return res


class SPConfig(Config):
    def_context = "sp"

    def __init__(self):
        Config.__init__(self)

    def vo_conf(self, vo_name):
        """Return the virtual organisation configuration for a given name.

        Args:
            vo_name: Identifier of the virtual organisation.

        Returns:
            dict | None: The configuration dictionary or ``None`` if missing.
        """
        try:
            return self.virtual_organization[vo_name]
        except KeyError:
            return None

    def ecp_endpoint(self, ipaddress):
        """Resolve which IdP entity should be used for an ECP client.

        Args:
            ipaddress: IP address of the user agent.

        Returns:
            str | None: IdP entity ID or ``None`` when no rule matches.
        """
        _ecp = self.getattr("ecp")
        if _ecp:
            for key, eid in _ecp.items():
                if re.match(key, ipaddress):
                    return eid

        return None


class IdPConfig(Config):
    def_context = "idp"

    def __init__(self):
        """Initialise IdP specific configuration defaults."""
        Config.__init__(self)


def config_factory(_type, config):
    """Instantiate and populate a configuration object for the given role.

    Args:
        _type: Entity type (``"sp"``, ``"idp"``, ``"aa"``, ``"pdp"`` or ``"aq"``).
        config: Configuration dictionary or path to a configuration module.

    Returns:
        Config: A populated configuration instance scoped to ``_type``.

    Raises:
        ValueError: If ``config`` is neither a mapping nor a string path.
    """
    if _type == "sp":
        conf = SPConfig()
    elif _type in ["aa", "idp", "pdp", "aq"]:
        conf = IdPConfig()
    else:
        conf = Config()

    if isinstance(config, dict):
        conf.load(copy.deepcopy(config))
    elif isinstance(config, str):
        conf.load_file(config)
    else:
        raise ValueError("Unknown type of config")

    conf.context = _type
    return conf
