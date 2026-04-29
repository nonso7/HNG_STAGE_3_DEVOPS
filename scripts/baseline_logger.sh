#!/bin/bash
CSV=/home/ubuntu/hng-detector/logs/baseline_history.csv
if [ ! -f "$CSV" ]; then
  echo "timestamp,mean,stddev,hour" > "$CSV"
fi
while true; do
  ts=$(date -Iseconds)
  hour=$(date -u +%H)
  data=$(curl -s http://localhost:8080/metrics 2>/dev/null)
  if [ -n "$data" ]; then
    mean=$(echo "$data" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('effective_mean',''))" 2>/dev/null)
    stddev=$(echo "$data" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('effective_stddev',''))" 2>/dev/null)
    echo "$ts,$mean,$stddev,$hour" >> "$CSV"
  fi
  sleep 60
done
