"""
Background task for periodic scan execution.
"""

import logging

from src.backend.db.session import SessionLocal
from src.backend.services.scan_executor import ScanExecutor
from src.backend.services.digest_service import DigestService

logger = logging.getLogger(__name__)


async def run_periodic_scans():
    """Execute all due scheduled scans and generate digests."""
    db = SessionLocal()
    try:
        executor = ScanExecutor(db)
        digest_service = DigestService(db)

        # Execute due scans
        results = await executor.execute_all_due_scans()
        logger.info(f"Executed {len(results)} scheduled scans")

        delivered = await digest_service.send_due_digests()
        logger.info("Delivered %s scheduled digests", len(delivered))

        logger.info("Periodic scan cycle complete")

    except Exception as e:
        logger.error(f"Periodic scan error: {e}")
    finally:
        db.close()
