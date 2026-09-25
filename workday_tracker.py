#!/usr/bin/env python3
"""Interactive daily standup and accomplishment logger."""

import json
import os
import sys
from datetime import datetime

LOGS_DIR = os.path.expanduser("~/grc_workday_logs")


def ensure_dirs():
    os.makedirs(LOGS_DIR, exist_ok=True)


def morning_standup():
    ensure_dirs()
    today = datetime.now().strftime("%A, %B %d, %Y")
    priorities = [input(f"{number}. Priority {number}: ").strip() for number in range(1, 4)]
    blockers = input("Any active blockers or dependencies? ").strip()
    path = os.path.join(LOGS_DIR, f"standup_{datetime.now():%Y-%m-%d}.json")
    with open(path, "w", encoding="utf-8") as output:
        json.dump({"date": today, "timestamp": datetime.now().isoformat(), "priorities": priorities, "blockers": blockers, "status": "IN_PROGRESS"}, output, indent=2)
    print(f"Morning standup logged to {path}")


def evening_winddown():
    ensure_dirs()
    today = datetime.now().strftime("%A, %B %d, %Y")
    milestones = []
    while True:
        entry = input("Completed milestone (or press Enter to finish): ").strip()
        if not entry:
            break
        milestones.append(entry)
    impact = input("Key quantifiable impact or metric: ").strip()
    with open(os.path.join(LOGS_DIR, "weekly_accomplishments.md"), "a", encoding="utf-8") as output:
        output.write(f"\n### {today}\n**Key Impact:** {impact}\n\n**Completed Milestones:**\n")
        output.writelines(f"- [x] {milestone}\n" for milestone in milestones)


if __name__ == "__main__":
    evening_winddown() if len(sys.argv) > 1 and sys.argv[1].lower() in {"--evening", "-e", "evening", "close"} else morning_standup()
