import json
import matplotlib.pyplot as plt
import numpy as np

with open('safebaseline.json', 'r') as f:
    safe_data = json.load(f)
safe_snapshots = safe_data['Baselines']['testapp']['Snapshots']
safe_rates = [s[0] for s in safe_snapshots]

with open('maliciousbaseline.json', 'r') as f:
    mal_data = json.load(f)
mal_snapshots = mal_data['Baselines']['testapp']['Snapshots']
mal_rates = [s[0] for s in mal_snapshots]

max_len = max(len(safe_rates), len(mal_rates))
safe_rates += [None] * (max_len - len(safe_rates))
mal_rates += [None] * (max_len - len(mal_rates))

x = np.arange(1, max_len + 1)

plt.figure(figsize=(12, 6))
plt.plot(x, safe_rates, label='Safe baseline', color='#2980b9', linewidth=2)
plt.plot(x, mal_rates, label='Malicious recording', color='#e74c3c', linewidth=2)
plt.axhline(y=1.2512, color='orange', linestyle='--', label='KNN Threshold (1.2512)')
plt.title('File Write Rate — Safe Baseline vs Malicious Recording')
plt.xlabel('Snapshot')
plt.ylabel('Write rate (files/sec)')
plt.legend()
plt.grid(True, linestyle='--', alpha=0.5)
plt.tight_layout()
plt.savefig('reports/knn-baseline-chart-updated.png')
plt.show()
