"""Keep the landing page's illustrative score lab aligned with Member 3's configuration."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
from app.scoring import CONFIG

if __name__ == '__main__':
    path = ROOT / 'frontend/src/fixtures/scoring_config.json'
    path.write_text(json.dumps(CONFIG, indent=2) + '\n', encoding='utf-8')
    print('Exported central scoring configuration for the illustrative landing-page lab')
