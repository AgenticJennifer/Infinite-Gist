from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db import SessionLocal, init_db
from app.main import ensure_default_user
from app.scanner import sync_detector_rules


def main() -> None:
    init_db()
    with SessionLocal() as db:
        ensure_default_user(db)
        sync_detector_rules(db)
    print("Database initialized.")


if __name__ == "__main__":
    main()
