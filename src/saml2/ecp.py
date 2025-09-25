#!/usr/bin/env python
#

"""Helpers for the SAML Enhanced Client or Proxy (ECP) profile.

The ECP profile allows a non-browser client to act as an intermediary between a
Service Provider and Identity Provider.  This module documents how the IdP can
generate SOAP-based authentication requests and parse the resulting responses
to manage a federated login flow.
"""
import logging

from saml2 import BINDING_PAOS
from saml2 import BINDING_SOAP
from saml2 import element_to_extension_element
from saml2 import saml
from saml2 import samlp
from saml2 import soap
from saml2.client_base import ACTOR
from saml2.client_base import MIME_PAOS
from saml2.ecp_client import SERVICE
from saml2.profile import ecp
from saml2.profile import paos
from saml2.response import authn_response
from saml2.schema import soapenv

# from saml2.client import Saml2Client
from saml2.server import Server


logger = logging.getLogger(__name__)


def ecp_capable(headers):
    """Determine if an HTTP request advertises ECP support.

    :param headers: Mapping of HTTP header names to values as provided by the
        client.
    :return: ``True`` if the request accepts PAOS responses and identifies the
        ECP service, otherwise ``False``.
    """

    if MIME_PAOS in headers["Accept"]:
        if "PAOS" in headers:
            if f'ver="{paos.NAMESPACE}";"{SERVICE}"' in headers["PAOS"]:
                return True

    return False


# noinspection PyUnusedLocal
def ecp_auth_request(cls, entityid=None, relay_state="", sign=None, sign_alg=None, digest_alg=None):
    """Create an ECP authentication request SOAP envelope.

    :param cls: The service implementation building the request, typically a
        :class:`saml2.client.Saml2Client` or compatible helper.
    :param entityid: EntityID of the IdP that should receive the request.
        ``None`` results in metadata-driven discovery.
    :param relay_state: Opaque state returned to the caller after successful
        login.
    :param sign: Controls whether the request is cryptographically signed.
    :param sign_alg: XML signature algorithm URI.
    :param digest_alg: XML signature digest algorithm URI.
    :return: A tuple ``(request_id, soap_envelope)``.
    """

    eelist = []

    # ----------------------------------------
    # <paos:Request>
    # ----------------------------------------
    my_url = cls.service_urls(BINDING_PAOS)[0]

    # must_understand and actor according to the standard
    #
    paos_request = paos.Request(
        must_understand="1",
        actor=ACTOR,
        response_consumer_url=my_url,
        service=SERVICE,
    )

    eelist.append(element_to_extension_element(paos_request))

    # ----------------------------------------
    # <samlp:AuthnRequest>
    # ----------------------------------------

    logger.info(f"entityid: {entityid}, binding: {BINDING_SOAP}")

    location = cls._sso_location(entityid, binding=BINDING_SOAP)
    req_id, authn_req = cls.create_authn_request(
        location,
        binding=BINDING_PAOS,
        service_url_binding=BINDING_PAOS,
        sign=sign,
        sign_alg=sign_alg,
        digest_alg=digest_alg,
    )

    body = soapenv.Body()
    body.extension_elements = [element_to_extension_element(authn_req)]

    # ----------------------------------------
    # <ecp:Request>
    # ----------------------------------------

    #        idp = samlp.IDPEntry(
    #            provider_id = "https://idp.example.org/entity",
    #            name = "Example identity provider",
    #            loc = "https://idp.example.org/saml2/sso",
    #            )
    #
    #        idp_list = samlp.IDPList(idp_entry= [idp])

    idp_list = None
    ecp_request = ecp.Request(
        actor=ACTOR,
        must_understand="1",
        provider_name=None,
        issuer=saml.Issuer(text=authn_req.issuer.text),
        idp_list=idp_list,
    )

    eelist.append(element_to_extension_element(ecp_request))

    # ----------------------------------------
    # <ecp:RelayState>
    # ----------------------------------------

    relay_state = ecp.RelayState(actor=ACTOR, must_understand="1", text=relay_state)

    eelist.append(element_to_extension_element(relay_state))

    header = soapenv.Header()
    header.extension_elements = eelist

    # ----------------------------------------
    # The SOAP envelope
    # ----------------------------------------

    soap_envelope = soapenv.Envelope(header=header, body=body)

    return req_id, str(soap_envelope)


def handle_ecp_authn_response(cls, soap_message, outstanding=None):
    """Parse an IdP authentication response delivered via the ECP channel.

    :param cls: Service object responsible for processing the ECP message.
    :param soap_message: Serialized SOAP envelope received from the IdP.
    :param outstanding: Outstanding request mapping used to validate the
        response.
    :return: Parsed authentication response together with the optional relay
        state element.
    """

    rdict = soap.class_instances_from_soap_enveloped_saml_thingies(soap_message, [paos, ecp, samlp])

    _relay_state = None
    for item in rdict["header"]:
        if item.c_tag == "RelayState" and item.c_namespace == ecp.NAMESPACE:
            _relay_state = item

    response = authn_response(cls.config, cls.service_urls(), outstanding, allow_unsolicited=True)

    response.loads(f"{rdict['body']}", False, soap_message)
    response.verify()
    cls.users.add_information_about_person(response.session_info())

    return response, _relay_state


def ecp_response(target_url, response):
    """Wrap an authentication response in an ECP SOAP envelope.

    :param target_url: Assertion Consumer Service URL the client should forward
        the response to.
    :param response: Parsed response object to embed in the SOAP body.
    :return: Serialized SOAP envelope ready to be sent to the client.
    """

    ecp_response = ecp.Response(assertion_consumer_service_url=target_url)
    header = soapenv.Header()
    header.extension_elements = [element_to_extension_element(ecp_response)]

    body = soapenv.Body()
    body.extension_elements = [element_to_extension_element(response)]

    soap_envelope = soapenv.Envelope(header=header, body=body)

    return f"{soap_envelope}"


class ECPServer(Server):
    """Minimal IdP server exposing helpers for the ECP profile."""

    def __init__(self, config_file="", config=None, cache=None):
        """Create a new ECP-capable IdP server instance.

        :param config_file: Path to the IdP configuration file.
        :param config: In-memory configuration object overriding
            ``config_file`` when provided.
        :param cache: Optional cache backend supplied to :class:`Server`.
        """

        Server.__init__(self, config_file, config, cache)

    def parse_ecp_authn_query(self):
        """Placeholder for parsing inbound ECP authentication queries."""

    def ecp_response(self):
        """Construct a bare ECP response envelope for testing purposes."""

        target_url = ""

        ecp_response = ecp.Response(assertion_consumer_service_url=target_url)
        header = soapenv.Body()
        header.extension_elements = [element_to_extension_element(ecp_response)]

        response = samlp.Response()
        body = soapenv.Body()
        body.extension_elements = [element_to_extension_element(response)]

        soap_envelope = soapenv.Envelope(header=header, body=body)

        return str(soap_envelope)
