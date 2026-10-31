"""Verify the running local combined app; record real API samples without resetting any data."""
import json
from html.parser import HTMLParser
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]


class Assets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.paths = []

    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if key in ('src', 'href') and value and value.startswith('/assets/'):
                self.paths.append(value)


def check():
    with httpx.Client(base_url='http://127.0.0.1:8000', timeout=45, trust_env=False) as client:
        def get(path):
            r = client.get(path)
            r.raise_for_status()
            return r.json()

        def post(path, body=None):
            r = client.post(path, json=body)
            r.raise_for_status()
            return r.json()

        assert get('/health')['demo_mode'] is True
        for path in ('/app', '/app/threats', '/app/assets', '/app/incidents', '/app/signals', '/app/analytics'):
            r = client.get(path)
            assert r.status_code == 200 and 'text/html' in r.headers['content-type']
        parser = Assets()
        parser.feed(client.get('/app').text)
        assert parser.paths
        for path in parser.paths:
            assert client.get(path).status_code == 200
        scenarios = []
        for scenario in ('no_cve_suspicious_chain', 'benign_maintenance', 'missing_telemetry'):
            result = post('/api/demo/inject-behaviour', {'scenario': scenario})
            assert result['handoff_status'] == 'delivered'
            target = result['alert_ids'][0] if result['alert_ids'] else result['incident_id']
            report = post(f'/api/alerts/{target}/investigate')
            if scenario == 'benign_maintenance':
                assert result['findings'] == [] and result['alert_ids'] == []
            else:
                assert report['integration_status'] == 'persisted'
                assert set(report['evidence_ids']) == {e['event_id'] for e in result['evidence']}
                assert len(get(f'/api/alerts/{target}/evidence')['items']) == len(result['evidence'])
            if scenario == 'missing_telemetry':
                assert any('Process telemetry not observed' in s for s in report['limitations'])
            sample = {'injection': result, 'investigation': report}
            (ROOT / f'docs/samples/shadow_{scenario}.json').write_text(json.dumps(sample, indent=2) + '\n', encoding='utf-8')
            scenarios.append({'scenario': scenario, 'findings': len(result['findings']),
                              'alert_ids': result['alert_ids'], 'generated_by': report['generated_by']})
        post('/api/demo/inject-cve', {'fixture_id': 'CVE-2024-21762'})
        post('/api/demo/simulate-signal', {'fixture_id': 'DEMO-VULN-001', 'signal_type': 'epss_jump'})
        assert get('/api/signals')['count'] > 0
        assert get('/api/signals/summary')['total'] > 0
        overview = get('/api/overview')
        assert overview['open_alerts'] >= 3 and overview['matched_assets'] >= 2
        assert get('/api/threats?relevant=true')['total'] > 0
        assert get('/api/threats?q=CVE-2024-21762')['total'] > 0
        assert len(get('/api/sectors/posture')['sectors']) == 6
        assert 'cohorts' in get('/api/insights/lead-time?days=90')
        assert 'certin_advisories' in get('/api/insights/india?limit=5')
        assert get('/api/export/stix?threat_id=CVE-2024-21762')['type'] == 'bundle'
        impact = post('/api/simulation/patch-impact', {'threat_id': 'CVE-2024-21762', 'patched_version': '7.4.11'})
        assert impact['after_affected_count'] == 0
        for path in ('/api/not-real', '/.env', '/assets/missing.js'):
            assert client.get(path).status_code == 404
        (ROOT / 'docs/samples/overview.json').write_text(json.dumps(overview, indent=2) + '\n', encoding='utf-8')
        result = {'base_url': str(client.base_url), 'api_health': 'ok', 'spa_routes': 6,
                  'build_assets_checked': len(parser.paths), 'scenarios': scenarios,
                  'patch_before_affected': impact['before_affected_count'], 'patch_after_affected': impact['after_affected_count'],
                  'threats': overview['threats_total'], 'open_alerts': overview['open_alerts'], 'browser_visual_check': 'unavailable'}
        (ROOT / 'artifacts/integration_http.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        return result


if __name__ == '__main__':
    print(json.dumps(check(), indent=2))
