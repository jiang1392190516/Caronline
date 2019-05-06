# -*- coding: utf-8 -*-
# Generated by Django 1.11.8 on 2019-05-06 06:14
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('userinfo', '0001_initial'),
        ('buy', '0001_initial'),
        ('sale', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='orders',
            name='buy_user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='buser', to='userinfo.UserInfo', verbose_name='买家'),
        ),
        migrations.AddField(
            model_name='orders',
            name='sale_user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='suser', to='userinfo.UserInfo', verbose_name='卖家'),
        ),
        migrations.AddField(
            model_name='cart',
            name='car',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='sale.Carinfo', verbose_name='车辆'),
        ),
        migrations.AddField(
            model_name='cart',
            name='suser',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='userinfo.UserInfo', verbose_name='买家'),
        ),
    ]
