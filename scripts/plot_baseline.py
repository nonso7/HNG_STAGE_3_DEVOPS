"""
plot_baseline.py — Generate Baseline-graph.png from baseline_history.csv

Reads the CSV produced by baseline_logger.sh and plots effective_mean
over time, with hourly slots visibly distinguishable.
"""

import csv
from datetime import datetime
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

CSV_PATH = '/home/ubuntu/hng-detector/logs/baseline_history.csv'
OUTPUT_PATH = '/home/ubuntu/hng-detector/screenshots/Baseline-graph.png'

timestamps = []
means = []
stddevs = []
hours = []

with open(CSV_PATH) as f:
    reader = csv.DictReader(f)
    for row in reader:
        try:
            ts = datetime.fromisoformat(row['timestamp'])
            mean = float(row['mean'])
            stddev = float(row['stddev'])
            hour = row['hour']
            timestamps.append(ts)
            means.append(mean)
            stddevs.append(stddev)
            hours.append(hour)
        except (ValueError, KeyError):
            continue

# Color points by hour for visual hourly distinction
unique_hours = sorted(set(hours))
colors = plt.cm.tab20.colors

fig, ax = plt.subplots(figsize=(14, 7))

# Plot the mean as a line
ax.plot(timestamps, means, '-', linewidth=1.5, label='effective_mean', color='#2563eb', zorder=2)

# Color-code points by hour to make hourly slots visually distinct
for i, hour in enumerate(unique_hours):
    hour_indices = [j for j, h in enumerate(hours) if h == hour]
    hour_ts = [timestamps[j] for j in hour_indices]
    hour_means = [means[j] for j in hour_indices]
    color = colors[i % len(colors)]
    ax.scatter(hour_ts, hour_means, s=20, c=[color], label=f'Hour {hour}', zorder=3)

# Compute and show per-hour averages as horizontal markers
for i, hour in enumerate(unique_hours):
    hour_means = [means[j] for j, h in enumerate(hours) if h == hour]
    if hour_means:
        avg = sum(hour_means) / len(hour_means)
        ax.axhline(y=avg, color=colors[i % len(colors)], linestyle='--', alpha=0.3)

ax.set_xlabel('Timestamp (UTC)', fontsize=12)
ax.set_ylabel('effective_mean (requests/second)', fontsize=12)
ax.set_title('Baseline effective_mean over time, by hourly slot', fontsize=14)
ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
ax.xaxis.set_major_locator(mdates.HourLocator(interval=1))
ax.grid(True, alpha=0.3)
ax.legend(loc='upper left', fontsize=9)

plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig(OUTPUT_PATH, dpi=120, bbox_inches='tight')
print(f"Saved: {OUTPUT_PATH}")
print(f"Data points: {len(means)}")
print(f"Hourly slots represented: {sorted(set(hours))}")
print(f"Mean range: {min(means):.2f} to {max(means):.2f}")
