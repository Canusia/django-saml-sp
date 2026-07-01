from django.test import TestCase
from onelogin.saml2.settings import OneLogin_Saml2_Settings

from sp.models import IdP


def make_idp(**kwargs):
    defaults = dict(
        name="Test IdP",
        base_url="https://sp.example.com",
        contact_name="Admin",
        contact_email="admin@example.com",
    )
    defaults.update(kwargs)
    return IdP.objects.create(**defaults)


class MetadataSigningFlagsTest(TestCase):
    def _metadata(self, idp):
        s = OneLogin_Saml2_Settings(settings=idp.sp_settings, sp_validation_only=True)
        result = s.get_sp_metadata()
        # python3-saml >= 1.16 returns str; older versions return bytes
        if isinstance(result, bytes):
            return result.decode("utf-8")
        return result

    def test_want_assertions_signed_reflected_in_metadata(self):
        idp = make_idp(want_assertions_signed=True, authn_requests_signed=False)
        # generate a cert so the library can produce signed-metadata XML
        idp.generate_certificate()
        self.assertIn("wantAssertionsSigned", idp.sp_settings["security"])
        self.assertTrue(idp.sp_settings["security"]["wantAssertionsSigned"])
        xml = self._metadata(idp)
        self.assertIn('WantAssertionsSigned="true"', xml)
        self.assertIn('AuthnRequestsSigned="false"', xml)

    def test_authn_requests_signed_reflected_in_metadata(self):
        idp = make_idp(want_assertions_signed=False, authn_requests_signed=True)
        # generate a cert — required when authn_requests_signed=True
        idp.generate_certificate()
        xml = self._metadata(idp)
        self.assertIn('AuthnRequestsSigned="true"', xml)
        self.assertIn('WantAssertionsSigned="false"', xml)
