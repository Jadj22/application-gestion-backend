# Generated for ORM Query Optimization — indexes for hot paths (Render EXPLAIN ANALYZE)
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0031_invoice_numero_per_business'),
    ]

    operations = [
        # Public catalog: business + is_published + statut (V1 has_dates branch scan)
        migrations.AddIndex(
            model_name='item',
            index=models.Index(fields=['business', 'is_published', 'statut'], name='idx_item_biz_pub_statut'),
        ),
        migrations.AddIndex(
            model_name='item',
            index=models.Index(fields=['business', 'category'], name='idx_item_biz_cat'),
        ),
        migrations.AddIndex(
            model_name='item',
            index=models.Index(fields=['business', 'statut'], name='idx_item_biz_statut2'),
        ),
        # Categories: filter parent_id + ordering nom
        migrations.AddIndex(
            model_name='category',
            index=models.Index(fields=['business', 'parent'], name='idx_cat_biz_parent'),
        ),
        # Maintenance tasks: filtres courants
        migrations.AddIndex(
            model_name='maintenancetask',
            index=models.Index(fields=['business', 'statut', 'created_at'], name='idx_task_biz_statut_date'),
        ),
        migrations.AddIndex(
            model_name='maintenancetask',
            index=models.Index(fields=['business', 'assigned_to'], name='idx_task_biz_assigned'),
        ),
        # Reservations: dashboard + disponibilité
        migrations.AddIndex(
            model_name='reservation',
            index=models.Index(fields=['business', 'statut'], name='idx_res_biz_statut'),
        ),
        migrations.AddIndex(
            model_name='reservation',
            index=models.Index(fields=['business', 'reserve_par'], name='idx_res_biz_reserver'),
        ),
        # ActivityLog: filtres action/acteur
        migrations.AddIndex(
            model_name='activitylog',
            index=models.Index(fields=['business', 'action'], name='idx_act_biz_action'),
        ),
        # Notification: user + lu
        migrations.AddIndex(
            model_name='notification',
            index=models.Index(fields=['business', 'user', 'lu'], name='idx_notif_biz_user_lu'),
        ),
        # BusinessMember: statut/role pour RBAC
        migrations.AddIndex(
            model_name='businessmember',
            index=models.Index(fields=['business', 'statut'], name='idx_member_biz_statut'),
        ),
    ]
