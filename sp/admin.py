from __future__ import unicode_literals

import json
from datetime import datetime, timezone

from django.contrib import admin, messages
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.urls import path
from django.utils.translation import gettext_lazy as _

from .models import IdP, IdPAttribute, IdPAttributeLog, IdPUserDefaultValue


IDP_EXPORT_EXCLUDE = {"id", "last_login", "last_import"}


def _serialize_idp(idp):
    """Serialize an IdP's config graph to a plain dict (JSON-ready via default=str)."""
    data = {
        f.name: f.value_from_object(idp)
        for f in idp._meta.concrete_fields
        if f.name not in IDP_EXPORT_EXCLUDE
    }
    data["attributes"] = [
        {
            "saml_attribute": a.saml_attribute,
            "mapped_name": a.mapped_name,
            "is_nameid": a.is_nameid,
            "always_update": a.always_update,
        }
        for a in idp.attributes.all()
    ]
    data["user_defaults"] = [
        {"field": d.field, "value": d.value} for d in idp.user_defaults.all()
    ]
    return data


_IDP_IMPORT_FIELDS = {
    f.name for f in IdP._meta.concrete_fields
} - IDP_EXPORT_EXCLUDE


def _apply_idp_fields(idp, entry):
    """Set known IdP config fields from an entry dict; ignore unknown keys."""
    for key, value in entry.items():
        if key not in _IDP_IMPORT_FIELDS:
            continue
        field = IdP._meta.get_field(key)
        setattr(idp, key, field.to_python(value) if value is not None else None)


def _import_one(entry):
    """Upsert one IdP config entry. Returns 'created' or 'updated'."""
    entity_id = (entry.get("entity_id") or "").strip()
    existing = IdP.objects.filter(entity_id=entity_id).first() if entity_id else None
    idp = existing or IdP()
    _apply_idp_fields(idp, entry)
    idp.save()
    # Replace child rows (safe for both create and update paths).
    idp.attributes.all().delete()
    idp.user_defaults.all().delete()
    for a in entry.get("attributes") or []:
        IdPAttribute.objects.create(
            idp=idp,
            saml_attribute=a.get("saml_attribute", ""),
            mapped_name=a.get("mapped_name", ""),
            is_nameid=bool(a.get("is_nameid", False)),
            always_update=bool(a.get("always_update", False)),
        )
    for d in entry.get("user_defaults") or []:
        IdPUserDefaultValue.objects.create(
            idp=idp, field=d.get("field", ""), value=d.get("value", ""))
    return "updated" if existing else "created"


class IdPAttributeInline(admin.TabularInline):
    model = IdPAttribute
    extra = 0


class IdPUserDefaultValueInline(admin.TabularInline):
    model = IdPUserDefaultValue
    extra = 0


class IdPAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "url_params",
        "last_import",
        "certificate_expires",
        "get_entity_id",
        "is_active",
        "sort_order",
        "last_login",
    )
    list_filter = ("is_active",)
    list_editable = ("sort_order", "is_active")
    actions = ("import_metadata", "generate_certificates", "duplicate_idp", "export_idp_json")
    inlines = (IdPUserDefaultValueInline, IdPAttributeInline)
    fieldsets = (
        (
            None,
            {
                "fields": (
                    "name",
                    "url_params",
                    "base_url",
                    "entity_id",
                    "notes",
                    "is_active",
                    "sort_order",
                )
            },
        ),
        (
            "SP Settings",
            {
                "fields": (
                    "contact_name",
                    "contact_email",
                    "authn_requests_signed",
                    "want_assertions_signed",
                    "x509_certificate",
                    "private_key",
                    "certificate_expires",
                )
            },
        ),
        (
            "IdP Metadata",
            {
                "fields": (
                    "metadata_url",
                    "verify_metadata_cert",
                    "metadata_xml",
                    "lowercase_encoding",
                    "last_import",
                )
            },
        ),
        (
            "Logins",
            {
                "fields": (
                    "auth_case_sensitive",
                    "create_users",
                    "associate_users",
                    "email_auth_errors_to_admins",
                    "auth_failed_message",
                    "log_response_attributes",
                    "respect_expiration",
                    "logout_triggers_slo",
                    "login_redirect",
                    "logout_redirect",
                    "last_login",
                )
            },
        ),
        (
            "Advanced",
            {
                "classes": ("collapse",),
                "fields": (
                    "username_prefix",
                    "username_suffix",
                    "state_timeout",
                    "require_attributes",
                    "authn_comparison",
                    "authn_context",
                    "logout_request_signed",
                    "logout_response_signed",
                    "authenticate_method",
                    "login_method",
                    "logout_method",
                    "prepare_request_method",
                    "update_user_method",
                ),
            },
        ),
    )
    readonly_fields = ("last_import", "last_login")
    change_list_template = "admin/sp/idp/change_list.html"

    def get_urls(self):
        custom = [
            path("import-json/", self.admin_site.admin_view(self.import_json_view),
                 name="sp_idp_import_json"),
        ]
        return custom + super().get_urls()

    def import_json_view(self, request):
        if not (self.has_add_permission(request)
                and self.has_change_permission(request)):
            raise PermissionDenied
        context = {
            **self.admin_site.each_context(request),
            "title": _("Import IdP configuration from JSON"),
            "opts": self.model._meta,
            "config_json": request.POST.get("config_json", ""),
        }
        if request.method == "POST":
            try:
                data = json.loads(context["config_json"])
            except json.JSONDecodeError as exc:
                messages.error(request, _("Invalid JSON: %s") % exc)
                return render(request, "admin/sp/idp/import_json.html", context)
            entries = data if isinstance(data, list) else [data]
            created = updated = failed = 0
            errors = []
            for entry in entries:
                try:
                    with transaction.atomic():
                        result = _import_one(entry)
                    created += result == "created"
                    updated += result == "updated"
                except Exception as exc:  # one bad entry must not abort the batch
                    failed += 1
                    errors.append("%s: %s" % (entry.get("name", "?"), exc))
            msg = _("Imported: %(c)d created, %(u)d updated, %(f)d failed.") % {
                "c": created, "u": updated, "f": failed}
            if errors:
                msg += " " + "; ".join(errors)
            (messages.warning if failed else messages.success)(request, msg)
            return redirect("admin:sp_idp_changelist")
        return render(request, "admin/sp/idp/import_json.html", context)

    def get_changeform_initial_data(self, request):
        return {
            "base_url": "{}://{}{}".format(
                request.scheme,
                request.get_host(),
                request.META["SCRIPT_NAME"].rstrip("/"),
            )
        }

    def generate_certificates(self, request, queryset):
        for idp in queryset:
            idp.generate_certificate()

    def import_metadata(self, request, queryset):
        for idp in queryset:
            idp.import_metadata()

    def duplicate_idp(self, request, queryset):
        count = 0
        for idp in queryset:
            idp.duplicate()
            count += 1
        self.message_user(request, "Duplicated %d IdP configuration(s)." % count)

    duplicate_idp.short_description = _("Duplicate selected IdP configuration(s)")

    def export_idp_json(self, request, queryset):
        payload = json.dumps(
            [_serialize_idp(idp) for idp in queryset], default=str, indent=2)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        resp = HttpResponse(payload, content_type="application/json")
        resp["Content-Disposition"] = (
            'attachment; filename="idp_config_export_%s.json"' % stamp)
        return resp

    export_idp_json.short_description = _(
        "Export selected IdP configuration(s) to JSON")

    def save_model(self, request, obj, form, change):
        super(IdPAdmin, self).save_model(request, obj, form, change)
        try:
            obj.import_metadata()
        except Exception:
            pass


admin.site.register(IdP, IdPAdmin)


class IdPAttributeLogAdmin(admin.ModelAdmin):
    list_display = ("idp", "nameid", "created_on")
    list_filter = ("idp",)
    search_fields = ("nameid",)
    readonly_fields = ("idp", "nameid", "attributes", "created_on")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


admin.site.register(IdPAttributeLog, IdPAttributeLogAdmin)
