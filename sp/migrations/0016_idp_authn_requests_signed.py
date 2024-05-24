# Generated by Django 4.2 on 2024-05-24 17:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sp', '0015_idp_logout_request_signed_idp_logout_response_signed'),
    ]

    operations = [
        migrations.AddField(
            model_name='idp',
            name='authn_requests_signed',
            field=models.BooleanField(default=False, verbose_name='Sign Authentication Request'),
        ),
    ]
