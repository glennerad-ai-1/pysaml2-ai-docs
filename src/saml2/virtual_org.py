import logging

from saml2.attribute_resolver import AttributeResolver
from saml2.saml import NAMEID_FORMAT_PERSISTENT


logger = logging.getLogger(__name__)


class VirtualOrg:
    """Coordinate attribute aggregation for a virtual organisation."""

    def __init__(self, sp, vorg, cnf):
        """Initialise helpers for attribute aggregation.

        Args:
            sp: Service provider client instance.
            vorg: Name of the virtual organisation.
            cnf: Virtual organisation configuration dictionary.
        """
        self.sp = sp  # The parent SP client instance
        self._name = vorg
        self.common_identifier = cnf["common_identifier"]
        try:
            self.member = cnf["member"]
        except KeyError:
            self.member = []
        try:
            self.nameid_format = cnf["nameid_format"]
        except KeyError:
            self.nameid_format = NAMEID_FORMAT_PERSISTENT

    def _cache_session(self, session_info):
        """Persist aggregated session information."""
        return True

    def _affiliation_members(self):
        """Retrieve virtual organisation members from metadata."""
        return self.sp.config.metadata.vo_members(self._name)

    def members_to_ask(self, name_id):
        """Return members that have not yet provided attributes for ``name_id``."""

        vo_members = self._affiliation_members()
        for member in self.member:
            if member not in vo_members:
                vo_members.append(member)

        # Remove the ones I have cached data from about this subject
        vo_members = [m for m in vo_members if not self.sp.users.cache.active(name_id, m)]
        logger.info("VO members (not cached): %s", vo_members)
        return vo_members

    def get_common_identifier(self, name_id):
        """Return the subject identifier used to query member IdPs."""
        (ava, _) = self.sp.users.get_identity(name_id)
        if ava == {}:
            return None

        ident = self.common_identifier

        try:
            return ava[ident][0]
        except KeyError:
            return None

    def do_aggregation(self, name_id):
        """Perform attribute aggregation across VO members.

        Args:
            name_id: Subject identifier whose attributes should be aggregated.

        Returns:
            bool: ``True`` if at least one member was queried, otherwise
            ``False``.
        """

        logger.info("** Do VO aggregation **\nSubjectID: %s, VO:%s", name_id, self._name)

        to_ask = self.members_to_ask(name_id)
        if to_ask:
            com_identifier = self.get_common_identifier(name_id)

            resolver = AttributeResolver(self.sp)
            # extends returns a list of session_infos
            for session_info in resolver.extend(com_identifier, self.sp.config.entityid, to_ask):
                _ = self._cache_session(session_info)

            logger.info(">Issuers: %s", self.sp.users.issuers_of_info(name_id))
            logger.info("AVA: %s", self.sp.users.get_identity(name_id))

            return True
        else:
            return False
