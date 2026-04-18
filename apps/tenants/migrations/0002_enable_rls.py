from django.db import migrations


RLS_TABLES = [
    'assets_asset',
    'assets_package',
    'vulnerabilities_finding',
    'vulnerabilities_risksnapshot',
]

# We join through assets_asset to get org for the package/finding tables
POLICIES = {
    'assets_asset': """
        CREATE POLICY tenant_isolation ON assets_asset
        USING (
            organization_id = current_setting('app.current_tenant_id', true)::uuid
        );
    """,
    'assets_package': """
        CREATE POLICY tenant_isolation ON assets_package
        USING (
            asset_id IN (
                SELECT id FROM assets_asset
                WHERE organization_id = current_setting('app.current_tenant_id', true)::uuid
            )
        );
    """,
    'vulnerabilities_finding': """
        CREATE POLICY tenant_isolation ON vulnerabilities_finding
        USING (
            asset_id IN (
                SELECT id FROM assets_asset
                WHERE organization_id = current_setting('app.current_tenant_id', true)::uuid
            )
        );
    """,
    'vulnerabilities_risksnapshot': """
        CREATE POLICY tenant_isolation ON vulnerabilities_risksnapshot
        USING (
            asset_id IN (
                SELECT id FROM assets_asset
                WHERE organization_id = current_setting('app.current_tenant_id', true)::uuid
            )
        );
    """,
}


class Migration(migrations.Migration):
    dependencies = [
        ('tenants', '0001_initial'),
        ('assets', '0001_initial'),
        ('vulnerabilities', '0001_initial'),
    ]

    operations = [
        migrations.RunSQL(
            sql=[
                # Enable RLS on each table
                *[
                    f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;"
                    for table in RLS_TABLES
                ],
                # FORCE RLS even for the table owner
                # Without this, the DB superuser bypasses all policies
                *[
                    f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;"
                    for table in RLS_TABLES
                ],
                # Create the policies
                *list(POLICIES.values()),
            ],
            reverse_sql=[
                *[f"DROP POLICY IF EXISTS tenant_isolation ON {t};" for t in RLS_TABLES],
                *[f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY;" for t in RLS_TABLES],
                *[f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY;" for t in RLS_TABLES],
            ]
        )
    ]