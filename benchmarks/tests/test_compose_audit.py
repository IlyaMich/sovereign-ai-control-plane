"""Path-resolution regressions without Podman or API dependency."""
import pytest
from benchmarks.compose_audit import resolve_audit_paths


def make_compose(root='/var/lib/sovereign', db=None, signing=None, reviewer_root=None):
    control_env = {
        'AUDIT_DB_PATH': db or root + '/audit.sqlite',
        'AUDIT_SIGNING_KEY_PATH': signing or root + '/audit-key.pem',
        'CONTROL_PLANE_API_KEY': 'secret-not-to-log',
    }
    return {'services': {
        'control-plane': {
            'environment': control_env,
            'volumes': [{'type': 'volume', 'source': 'project_audit-data', 'target': root},
                        {'type': 'bind', 'source': '/my-policy', 'target': '/policy-active'}],
        },
        'audit-reviewer': {
            'volumes': [{'type': 'volume', 'source': 'project_audit-data',
                         'target': reviewer_root or root, 'read_only': True}],
        },
    }}


def test_default_audit_paths():
    a = resolve_audit_paths(make_compose())
    assert a.database == '/var/lib/sovereign/audit.sqlite'
    assert a.public_key == '/var/lib/sovereign/audit-key.pub.pem'


def test_configurable_paths():
    a = resolve_audit_paths(make_compose(
        root='/opt/audit-volume', db='/opt/audit-volume/sql/main.sqlite',
        signing='/opt/audit-volume/keys/main.pem'))
    assert a.database == '/opt/audit-volume/sql/main.sqlite'
    assert a.public_key == '/opt/audit-volume/keys/main.pub.pem'


def test_reviewer_mount_translation():
    a = resolve_audit_paths(make_compose('/mount/audit', reviewer_root='/readonly/audit'))
    assert a.database == '/readonly/audit/audit.sqlite'
    assert a.public_key == '/readonly/audit/audit-key.pub.pem'


def test_outside_shared_audit_volume_fails():
    with pytest.raises(ValueError, match='shared'):
        resolve_audit_paths(make_compose(db='/unmounted/audit.sqlite'))


def test_list_style_environment_supported():
    c = make_compose()
    c['services']['control-plane']['environment'] = [
        'AUDIT_DB_PATH=/var/lib/sovereign/audit.sqlite',
        'AUDIT_SIGNING_KEY_PATH=/var/lib/sovereign/audit-key.pem',
    ]
    assert resolve_audit_paths(c).database == '/var/lib/sovereign/audit.sqlite'
