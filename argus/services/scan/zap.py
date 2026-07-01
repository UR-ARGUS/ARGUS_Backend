import time
import urllib.request
import json
from pathlib import Path
from argus.services.capture.capture_pipeline.docker_base import DockerBaseService
from argus.db import get_session
from argus.models.capture import CaptureJob, JobPhase
from argus.models.alert import AlertStatus, AlertCategory, AlertPriority, Alert
from argus.models.domain import Domain
from sqlalchemy.orm.session import Session
from sqlalchemy import and_
import subprocess

# ============================================================================
# 0.0. Service Configuration
# ============================================================================
SERVICE_NAME = "ZAP-DAST"


class ZAPDASTService(DockerBaseService):
    def __init__(self):
        super().__init__(SERVICE_NAME)

    # ========================================================================
    # 0.2. Entry Point
    # ========================================================================
    def run(self, *args, **kwargs):
        """Docker Compose Entrypoint"""
        if not args or not args[0].endswith(".json"):
            self.logger.error("Invalid arguments. Usage: python zap_dast.py <job_data.json> [AlertLevel...]")
            return 1

        job_file = args[0]
        alert_levels = []
        if len(args) > 1:
            alert_levels = args[1:]

        try:
            with open(job_file, 'r', encoding='utf-8') as f:
                job_data = json.load(f)
            
            db_session = get_session()
            job: CaptureJob = db_session.query(CaptureJob).filter(CaptureJob.job_id == job_data["job_id"]).first()
            if not job:
                self.logger.error(f"Job not found: {job_data['job_id']}")
                return 1

            return self.process_job(job, db_session, alert_levels)
        except Exception as e:
            self.logger.exception("Exception in main process.")
            return 1

    # ========================================================================
    # 0.3. Job Processor
    # ========================================================================
    def process_job(self, job: CaptureJob, db_session: Session, alert_levels: list[str]) -> int:
        # Phase 1: DAST Scan
        self.logger.info(f"Starting DAST scan for job {job.job_id} on {job.target_url}")
        
        dockerfile = Path(__file__).parent / "Dockerfile"
        context_dir = dockerfile.parent
        
        # Pass Alert Levels as Environment Variables
        alert_env = {f"ALERT_LEVEL_{i}": level for i, level in enumerate(alert_levels)}
        
        # Construct Command
        cmd = [
            "docker-compose",
            "run",
            "--rm",
            "-e", "USER_API_KEY",
            *self._add_gpu_flags() if self.use_gpu else [],
            *["-e", f"{k}={v}" for k, v in alert_env.items()],
            "-v", f"{job.result_path}:/zap/wrk/:rw",
            "selenium-capture"
        ]
        
        full_command = " ".join(cmd)
        self.logger.info(f"Executing command: {full_command}")
        
        try:
            # Run the capture pipeline
            self.execute_command(full_command, cwd=str(context_dir))
            
            # Parse and save results
            self.parse_and_save_results(job, db_session)
            
            return 0
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"DAST scan failed: {e}")
            job.status = JobPhase.FAILED
            db_session.commit()
            return 1
        except Exception as e:
            self.logger.exception("An error occurred during DAST processing")
            job.status = JobPhase.FAILED
            db_session.commit()
            return 1
    
    def parse_and_save_results(self, job: CaptureJob, db_session: Session):
        result_dir = Path(job.result_path)
        zap_results = list(result_dir.glob("*.json"))
        if not zap_results:
            self.logger.warning("No results found")
            return
        
        # Assuming the last one is the latest
        latest_result = max(zap_results, key=lambda x: x.stat().st_mtime)
        self.logger.info(f"Parsing results from: {latest_result}")
        
        with open(latest_result, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        alerts_data = data.get("alerts", [])
        total_alerts = len(alerts_data)
        self.logger.info(f"Found {total_alerts} alerts.")
        
        # Update status and results
        job.status = JobPhase.SCAN_COMPLETED
        job.dast_result = latest_result.name
        db_session.commit()
        
        if total_alerts > 0:
            self._save_alerts_to_db(job, alerts_data, db_session)
    
    def _save_alerts_to_db(self, job: CaptureJob, alerts_data: list, db_session: Session):
        # Get or create domain
        domain = db_session.query(Domain).filter(Domain.url == job.target_url).first()
        if not domain:
            domain = Domain(url=job.target_url, name="Unknown")
            db_session.add(domain)
            db_session.commit()
            self.logger.info(f"Created new domain: {job.target_url}")
        
        for alert_data in alerts_data:
            risk = alert_data["risk"]
            try:
                priority = AlertPriority(risk.lower())
            except ValueError:
                self.logger.warning(f"Unknown risk level: {risk}, defaulting to MEDIUM")
                priority = AlertPriority.MEDIUM
            
            # Check if alert already exists
            existing_alert = db_session.query(Alert).filter(
                Alert.job_id == job.job_id,
                Alert.category == AlertCategory.DAST,
                Alert.name == alert_data["name"]
            ).first()
            
            if existing_alert:
                continue
            
            alert = Alert(
                domain_id=domain.id,
                job_id=job.job_id,
                category=AlertCategory.DAST,
                priority=priority,
                status=AlertStatus.ACTIVE,
                name=alert_data["name"],
                description=alert_data["description"],
                full_url=alert_data["fullurl"],
                method=alert_data.get("method", "GET"),
                param=alert_data.get("param", ""),
                attack=alert_data.get("attack", ""),
                evidence=alert_data.get("evidence", ""),
                confidence=alert_data.get("confidence", "Medium"),
                severity=alert_data.get("severity", "Medium"),
                cweid=alert_data.get("cweid", 0),
                wascid=alert_data.get("wascid", ""),
                source="ZAP-DAST",
                created_by=job.created_by
            )
            db_session.add(alert)
        
        db_session.commit()
        self.logger.info(f"Saved {len(alerts_data)} DAST alerts to database")


# ============================================================================
# 0.4. Main Execution Block
# ============================================================================
if __name__ == "__main__":
    service = ZAPDASTService()
    exit(service.run(*sys.argv[1:]))
