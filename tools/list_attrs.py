"""List attribute keys from OTel semantic-convention registries (definition/2 and legacy group formats).
Usage: python3 -I list_attrs.py <registry.yaml> [...]"""
import sys, yaml
for f in sys.argv[1:]:
    d = yaml.safe_load(open(f, encoding='utf-8'))
    items = list(d.get('attributes') or [])
    for g in d.get('groups') or []:
        items += [a for a in (g.get('attributes') or []) if 'id' in a]
    for a in items:
        k = a.get('key') or a.get('id')
        t = a.get('type')
        t = 'enum' if isinstance(t, dict) else t
        b = (a.get('brief') or '').strip().replace('\n', ' ')
        dep = 'DEPR ' if a.get('deprecated') else ''
        print(f"{k:42s} {str(a.get('stability','')):11s} {str(t):10s} {dep}{b[:120]}")
