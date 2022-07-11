# Generated by Django 3.1 on 2022-06-05 13:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0004_userprofile'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userprofile',
            name='address_line_1',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='address_line_2',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='city',
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='country',
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='profile_picture',
            field=models.ImageField(blank=True, null=True, upload_to='userprofile'),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='state',
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
    ]