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


class AttributeLogTest(TestCase):
    class FakeSAML:
        def __init__(self, nameid, attributes):
            self._nameid = nameid
            self._attributes = attributes

        def get_nameid(self):
            return self._nameid

        def get_attribute(self, name):
            value = self._attributes.get(name)
            return value

        def get_attributes(self):
            return self._attributes

    def test_log_attributes_creates_one_row_with_all_attributes(self):
        idp = make_idp()
        saml = self.FakeSAML(
            "user@example.com",
            {"eppn": ["user@example.com"], "displayName": ["Test User"]},
        )
        log = idp.log_attributes(saml)
        self.assertEqual(idp.attribute_logs.count(), 1)
        self.assertEqual(log.nameid, "user@example.com")
        self.assertEqual(log.attributes["displayName"], ["Test User"])

    def test_log_attributes_tolerates_missing_nameid(self):
        idp = make_idp()

        class NoNameID(self.FakeSAML):
            def get_nameid(self):
                raise ValueError("no nameid")

        log = idp.log_attributes(NoNameID(None, {"a": ["1"]}))
        self.assertEqual(log.nameid, "")
        self.assertEqual(log.attributes, {"a": ["1"]})

    def test_log_attributes_uses_mapped_nameid(self):
        from sp.models import IdPAttribute

        idp = make_idp()
        IdPAttribute.objects.create(
            idp=idp, saml_attribute="eppn", mapped_name="username", is_nameid=True
        )
        saml = self.FakeSAML(
            "raw-transient-id",
            {"eppn": ["mapped@example.com"]},
        )
        log = idp.log_attributes(saml)
        self.assertEqual(log.nameid, "mapped@example.com")


from django.contrib.auth import get_user_model

from sp.backends import MyCESAMLAuthenticationBackend


class FakeAuthSAML:
    def __init__(self, nameid):
        self._nameid = nameid

    def get_nameid(self):
        return self._nameid

    def get_attribute(self, name):
        return None


class AuthBackendTest(TestCase):
    def setUp(self):
        self.backend = MyCESAMLAuthenticationBackend()
        self.idp = make_idp()
        self.User = get_user_model()

    def test_returns_existing_user(self):
        user = self.User.objects.create(username="user@example.com")
        result = self.backend.authenticate(
            None, idp=self.idp, saml=FakeAuthSAML("user@example.com")
        )
        self.assertEqual(result, user)

    def test_missing_user_returns_none_and_logs_error_when_enabled(self):
        self.idp.email_auth_errors_to_admins = True
        self.idp.save()
        with self.assertLogs("sp.backends", level="ERROR") as cm:
            result = self.backend.authenticate(
                None, idp=self.idp, saml=FakeAuthSAML("ghost@example.com")
            )
        self.assertIsNone(result)
        self.assertTrue(any("ghost@example.com" in m for m in cm.output))

    def test_missing_user_logs_info_when_disabled(self):
        self.idp.email_auth_errors_to_admins = False
        self.idp.save()
        with self.assertLogs("sp.backends", level="INFO") as cm:
            result = self.backend.authenticate(
                None, idp=self.idp, saml=FakeAuthSAML("ghost@example.com")
            )
        self.assertIsNone(result)
        self.assertFalse(any(rec.startswith("ERROR") for rec in cm.output))

    def test_case_insensitive_lookup_returns_user(self):
        user = self.User.objects.create(username="User@Example.com")
        self.idp.auth_case_sensitive = False
        self.idp.save()
        result = self.backend.authenticate(
            None, idp=self.idp, saml=FakeAuthSAML("user@example.com")
        )
        self.assertEqual(result, user)

    def test_multiple_matches_returns_none(self):
        self.User.objects.create(username="user@example.com")
        self.User.objects.create(username="USER@EXAMPLE.COM")
        self.idp.auth_case_sensitive = False
        self.idp.save()
        with self.assertLogs("sp.backends", level="INFO"):
            result = self.backend.authenticate(
                None, idp=self.idp, saml=FakeAuthSAML("user@example.com")
            )
        self.assertIsNone(result)

    def test_malformed_nameid_returns_none(self):
        class BrokenSAML(FakeAuthSAML):
            def get_nameid(self):
                raise ValueError("malformed nameid")

        with self.assertLogs("sp.backends", level="INFO"):
            result = self.backend.authenticate(
                None, idp=self.idp, saml=BrokenSAML("")
            )
        self.assertIsNone(result)


from django.template.loader import render_to_string


class AuthFailedMessageTest(TestCase):
    def test_field_default_blank(self):
        idp = make_idp()
        self.assertEqual(idp.auth_failed_message, "")

    def test_unauth_template_renders_custom_message(self):
        idp = make_idp(auth_failed_message="You have no MyCE account. Contact support.")
        html = render_to_string(
            "sp/unauth.html",
            {"idp": idp, "auth_failed_message": idp.auth_failed_message},
        )
        self.assertIn("You have no MyCE account. Contact support.", html)


from sp.models import IdPAttribute, IdPUserDefaultValue


class DuplicateIdPTest(TestCase):
    def test_duplicate_copies_config_and_children(self):
        idp = make_idp(name="Primary", want_assertions_signed=True)
        IdPAttribute.objects.create(
            idp=idp, saml_attribute="eppn", mapped_name="username", is_nameid=True
        )
        IdPUserDefaultValue.objects.create(idp=idp, field="is_staff", value="0")

        copy = idp.duplicate()

        self.assertNotEqual(copy.pk, idp.pk)
        self.assertEqual(copy.name, "Primary (copy)")
        self.assertTrue(copy.want_assertions_signed)
        self.assertEqual(copy.attributes.count(), 1)
        self.assertEqual(copy.attributes.first().saml_attribute, "eppn")
        self.assertEqual(copy.user_defaults.count(), 1)
        # original untouched
        self.assertEqual(idp.attributes.count(), 1)

    def test_duplicate_accepts_custom_name(self):
        idp = make_idp(name="Primary")
        copy = idp.duplicate(name="Secondary")
        self.assertEqual(copy.name, "Secondary")

    def test_duplicate_does_not_share_jsonfield_containers(self):
        idp = make_idp(name="Primary", url_params={"app": "one"})
        clone = idp.duplicate()
        # Mutating the clone's JSON containers must not touch the original's.
        clone.url_params["app"] = "two"
        clone.authn_context.append("extra")
        self.assertEqual(idp.url_params, {"app": "one"})
        self.assertNotIn("extra", idp.authn_context)


from sp.views import _should_log_response


class ShouldLogResponseTest(TestCase):
    def test_toggle_on_normal_state_returns_true(self):
        idp = make_idp(log_response_attributes=True)
        self.assertTrue(_should_log_response(idp, "/dashboard"))

    def test_toggle_on_test_state_returns_false(self):
        idp = make_idp(log_response_attributes=True)
        self.assertFalse(_should_log_response(idp, "test:/foo"))

    def test_toggle_off_returns_false(self):
        idp = make_idp(log_response_attributes=False)
        self.assertFalse(_should_log_response(idp, "/dashboard"))


class LogResponseAttributesToggleTest(TestCase):
    class FakeSAML:
        def get_nameid(self):
            return "user@example.com"

        def get_attributes(self):
            return {"eppn": ["user@example.com"]}

    def test_toggle_default_true(self):
        idp = make_idp()
        self.assertTrue(idp.log_response_attributes)

    def test_logs_when_enabled(self):
        idp = make_idp(log_response_attributes=True)
        idp.log_attributes(self.FakeSAML())
        self.assertEqual(idp.attribute_logs.count(), 1)

    def test_disabled_toggle_gates_logging_at_call_site(self):
        # Exercise the real ACS guard (_should_log_response), not an inlined copy.
        from sp.views import _should_log_response

        idp = make_idp(log_response_attributes=False)
        self.assertFalse(_should_log_response(idp, None))
        self.assertEqual(idp.attribute_logs.count(), 0)


import json as _json
from django.contrib.admin.sites import AdminSite
from django.test import RequestFactory

from sp.admin import IdPAdmin


class ExportIdPJsonTest(TestCase):
    def test_export_includes_config_key_and_children(self):
        idp = make_idp(name="Exp", entity_id="urn:idp:exp", private_key="SECRETKEY")
        IdPAttribute.objects.create(
            idp=idp, saml_attribute="eppn", mapped_name="username", is_nameid=True)
        IdPUserDefaultValue.objects.create(idp=idp, field="is_staff", value="0")

        admin = IdPAdmin(IdP, AdminSite())
        resp = admin.export_idp_json(
            RequestFactory().get("/"), IdP.objects.filter(pk=idp.pk))

        self.assertEqual(resp["Content-Type"], "application/json")
        self.assertIn("attachment", resp["Content-Disposition"])
        data = _json.loads(resp.content)
        self.assertEqual(len(data), 1)
        entry = data[0]
        self.assertEqual(entry["entity_id"], "urn:idp:exp")
        self.assertEqual(entry["private_key"], "SECRETKEY")  # 1a: sensitive included
        self.assertNotIn("id", entry)
        self.assertNotIn("last_login", entry)
        self.assertEqual(entry["attributes"][0]["saml_attribute"], "eppn")
        self.assertTrue(entry["attributes"][0]["is_nameid"])
        self.assertEqual(entry["user_defaults"][0]["field"], "is_staff")


from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_logged_in
from django.urls import reverse


def _disconnect_login_signal():
    """The django_login_history post_login receiver crashes on the test
    client's missing REMOTE_ADDR. Disconnect for the duration of the test."""
    receivers = list(user_logged_in.receivers)
    user_logged_in.receivers = []
    return receivers


def _reconnect_login_signal(receivers):
    user_logged_in.receivers = receivers


class ImportIdPJsonTest(TestCase):
    def setUp(self):
        User = get_user_model()
        self._saved_login_receivers = _disconnect_login_signal()
        self.admin_user = User.objects.create(
            username="root@example.com", email="root@example.com",
            is_staff=True, is_superuser=True)
        self.client.force_login(self.admin_user)
        self.url = reverse("admin:sp_idp_import_json")

    def tearDown(self):
        _reconnect_login_signal(self._saved_login_receivers)

    def _payload(self, **over):
        entry = {
            "name": "New IdP", "base_url": "https://sp.example.com",
            "contact_name": "A", "contact_email": "a@example.com",
            "entity_id": "urn:new",
            "attributes": [
                {"saml_attribute": "eppn", "mapped_name": "username", "is_nameid": True}],
            "user_defaults": [{"field": "is_staff", "value": "0"}],
        }
        entry.update(over)
        return _json.dumps(entry)

    def test_get_renders_textarea(self):
        resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'name="config_json"')

    def test_post_creates_new_idp_with_children(self):
        resp = self.client.post(self.url, {"config_json": self._payload()})
        self.assertEqual(resp.status_code, 302)
        idp = IdP.objects.get(entity_id="urn:new")
        self.assertEqual(idp.name, "New IdP")
        self.assertEqual(idp.attributes.count(), 1)
        self.assertEqual(idp.user_defaults.count(), 1)

    def test_post_upserts_by_entity_id_and_replaces_children(self):
        existing = make_idp(name="Old", entity_id="urn:same")
        IdPAttribute.objects.create(idp=existing, saml_attribute="old_attr")
        resp = self.client.post(self.url, {"config_json": self._payload(
            name="Updated", entity_id="urn:same",
            attributes=[{"saml_attribute": "new_attr", "mapped_name": "username"}],
            user_defaults=[])})
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(IdP.objects.filter(entity_id="urn:same").count(), 1)
        existing.refresh_from_db()
        self.assertEqual(existing.name, "Updated")
        self.assertEqual(existing.attributes.count(), 1)
        self.assertEqual(existing.attributes.first().saml_attribute, "new_attr")

    def test_accepts_json_array(self):
        payload = "[%s, %s]" % (self._payload(entity_id="urn:a"),
                                self._payload(entity_id="urn:b"))
        self.client.post(self.url, {"config_json": payload})
        self.assertTrue(IdP.objects.filter(entity_id="urn:a").exists())
        self.assertTrue(IdP.objects.filter(entity_id="urn:b").exists())

    def test_malformed_json_writes_nothing(self):
        before = IdP.objects.count()
        resp = self.client.post(self.url, {"config_json": "{not valid"})
        self.assertEqual(resp.status_code, 200)  # re-rendered form
        self.assertEqual(IdP.objects.count(), before)

    def test_permission_denied_for_non_staff(self):
        User = get_user_model()
        plain = User.objects.create(username="plain@example.com", email="plain@example.com")
        self.client.force_login(plain)
        resp = self.client.get(self.url)
        self.assertIn(resp.status_code, (302, 403))  # admin_view redirects or denies

    def test_valid_json_but_not_object_is_handled(self):
        before = IdP.objects.count()
        resp = self.client.post(self.url, {"config_json": '"just a string"'})
        self.assertIn(resp.status_code, (200, 302))  # no 500
        self.assertEqual(IdP.objects.count(), before)


import datetime
from django.utils import timezone

from sp.admin import _import_one


class RoundTripIdPJsonTest(TestCase):
    def test_export_then_import_restores_config(self):
        cert_expires = timezone.make_aware(datetime.datetime(2027, 1, 1))
        src = make_idp(name="Src", entity_id="urn:rt", want_assertions_signed=True,
                       private_key="KEY", certificate_expires=cert_expires)
        IdPAttribute.objects.create(
            idp=src, saml_attribute="eppn", mapped_name="username", is_nameid=True)
        IdPUserDefaultValue.objects.create(idp=src, field="is_staff", value="1")

        admin = IdPAdmin(IdP, AdminSite())
        resp = admin.export_idp_json(
            RequestFactory().get("/"), IdP.objects.filter(pk=src.pk))
        src.delete()
        self.assertEqual(IdP.objects.filter(entity_id="urn:rt").count(), 0)

        for entry in _json.loads(resp.content):
            _import_one(entry)

        restored = IdP.objects.get(entity_id="urn:rt")
        self.assertEqual(restored.name, "Src")
        self.assertTrue(restored.want_assertions_signed)
        self.assertEqual(restored.private_key, "KEY")
        self.assertEqual(restored.attributes.first().saml_attribute, "eppn")
        self.assertEqual(restored.user_defaults.first().value, "1")
        self.assertEqual(restored.certificate_expires, cert_expires)
        self.assertEqual(restored.certificate_expires.year, 2027)
        self.assertEqual(restored.certificate_expires.month, 1)
        self.assertEqual(restored.certificate_expires.day, 1)
