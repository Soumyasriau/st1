"""
ThreatLens AI - Database Layer
SQLite schema and queries for assessments, findings, threat scenarios, and mitigation statuses.
"""

import sqlite3
import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "threatlens.db")


def get_db_connection(db_path: str = DB_FILE) -> sqlite3.Connection:
    """Establish and return a connection to the SQLite database with row factory."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: str = DB_FILE) -> None:
    """Initialize database tables with indexes for high performance."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS assessments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_url TEXT NOT NULL,
        hostname TEXT NOT NULL,
        scan_timestamp TEXT NOT NULL,
        overall_score INTEGER NOT NULL,
        risk_summary TEXT NOT NULL,       -- JSON: {critical, high, medium, low, total_findings}
        checks_summary TEXT NOT NULL,     -- JSON: {passed, warning, failed, total}
        https_status TEXT NOT NULL,
        tls_status TEXT NOT NULL,
        headers_status TEXT NOT NULL,
        executive_summary TEXT NOT NULL,
        raw_results TEXT NOT NULL          -- Full JSON dump of scan findings & metadata
    );

    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        assessment_id INTEGER NOT NULL,
        finding_code TEXT NOT NULL,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        status TEXT NOT NULL,             -- PASS, WARNING, FAIL, NOT_ASSESSED
        severity TEXT NOT NULL,           -- Low, Medium, High, Critical
        evidence TEXT NOT NULL,
        description TEXT NOT NULL,
        recommendation TEXT NOT NULL,
        FOREIGN KEY (assessment_id) REFERENCES assessments (id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS threat_scenarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        assessment_id INTEGER NOT NULL,
        threat_id TEXT NOT NULL,
        finding_code TEXT NOT NULL,
        threat_category TEXT NOT NULL,    -- STRIDE: Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege
        title TEXT NOT NULL,
        attack_scenario TEXT NOT NULL,
        likelihood INTEGER NOT NULL,      -- 1 to 5
        impact INTEGER NOT NULL,          -- 1 to 5
        risk_score INTEGER NOT NULL,      -- likelihood * impact (1 to 25)
        severity TEXT NOT NULL,           -- Low, Medium, High, Critical
        rationale TEXT NOT NULL,
        mitigation TEXT NOT NULL,
        verification_steps TEXT NOT NULL,
        FOREIGN KEY (assessment_id) REFERENCES assessments (id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS mitigation_status (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        assessment_id INTEGER NOT NULL,
        threat_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Open',  -- Open, In Progress, Mitigated, Accepted
        notes TEXT DEFAULT '',
        updated_at TEXT NOT NULL,
        FOREIGN KEY (assessment_id) REFERENCES assessments (id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_assessments_hostname ON assessments(hostname);
    CREATE INDEX IF NOT EXISTS idx_assessments_timestamp ON assessments(scan_timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_findings_assessment ON findings(assessment_id);
    CREATE INDEX IF NOT EXISTS idx_threats_assessment ON threat_scenarios(assessment_id);
    """)

    conn.commit()
    conn.close()


def calculate_severity(risk_score: int) -> str:
    """Return severity label according to project risk scoring methodology:
    1-4: Low, 5-9: Medium, 10-16: High, 17-25: Critical
    """
    if risk_score >= 17:
        return "Critical"
    elif risk_score >= 10:
        return "High"
    elif risk_score >= 5:
        return "Medium"
    return "Low"


def save_assessment(assessment_data: Dict[str, Any], db_path: str = DB_FILE) -> int:
    """Store complete assessment results, findings, threats, and mitigation items in a transaction."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO assessments (
                target_url, hostname, scan_timestamp, overall_score,
                risk_summary, checks_summary, https_status, tls_status,
                headers_status, executive_summary, raw_results
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            assessment_data.get("target_url"),
            assessment_data.get("hostname"),
            assessment_data.get("scan_timestamp", datetime.now(timezone.utc).isoformat() + "Z"),
            assessment_data.get("overall_score", 0),
            json.dumps(assessment_data.get("risk_summary", {})),
            json.dumps(assessment_data.get("checks_summary", {})),
            assessment_data.get("https_status", "UNKNOWN"),
            assessment_data.get("tls_status", "UNKNOWN"),
            assessment_data.get("headers_status", "UNKNOWN"),
            assessment_data.get("executive_summary", ""),
            json.dumps(assessment_data.get("raw_results", {}))
        ))
        assessment_id = cursor.lastrowid

        # Insert findings
        for f in assessment_data.get("findings", []):
            cursor.execute("""
                INSERT INTO findings (
                    assessment_id, finding_code, title, category, status,
                    severity, evidence, description, recommendation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                assessment_id,
                f.get("finding_code", "TL-FIND"),
                f.get("title", ""),
                f.get("category", "General"),
                f.get("status", "NOT_ASSESSED"),
                f.get("severity", "Low"),
                f.get("evidence", ""),
                f.get("description", ""),
                f.get("recommendation", "")
            ))

        # Insert threat scenarios and default mitigation statuses
        for t in assessment_data.get("threat_scenarios", []):
            likelihood = int(t.get("likelihood", 1))
            impact = int(t.get("impact", 1))
            risk_score = likelihood * impact
            severity = calculate_severity(risk_score)

            cursor.execute("""
                INSERT INTO threat_scenarios (
                    assessment_id, threat_id, finding_code, threat_category,
                    title, attack_scenario, likelihood, impact, risk_score,
                    severity, rationale, mitigation, verification_steps
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                assessment_id,
                t.get("threat_id", "TL-THR"),
                t.get("finding_code", ""),
                t.get("threat_category", "Information Disclosure"),
                t.get("title", ""),
                t.get("attack_scenario", ""),
                likelihood,
                impact,
                risk_score,
                severity,
                t.get("rationale", ""),
                t.get("mitigation", ""),
                t.get("verification_steps", "")
            ))

            cursor.execute("""
                INSERT INTO mitigation_status (
                    assessment_id, threat_id, status, notes, updated_at
                ) VALUES (?, ?, 'Open', '', ?)
            """, (
                assessment_id,
                t.get("threat_id"),
                datetime.now(timezone.utc).isoformat() + "Z"
            ))

        conn.commit()
        return assessment_id
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()


def get_all_assessments(limit: int = 50, offset: int = 0, search: str = "", db_path: str = DB_FILE) -> List[Dict[str, Any]]:
    """Retrieve list of assessments with parsed JSON summaries."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    if search:
        query = """
            SELECT * FROM assessments
            WHERE hostname LIKE ? OR target_url LIKE ?
            ORDER BY id DESC LIMIT ? OFFSET ?
        """
        cursor.execute(query, (f"%{search}%", f"%{search}%", limit, offset))
    else:
        query = """
            SELECT * FROM assessments
            ORDER BY id DESC LIMIT ? OFFSET ?
        """
        cursor.execute(query, (limit, offset))

    rows = cursor.fetchall()
    results = []
    for row in rows:
        item = dict(row)
        item["risk_summary"] = json.loads(item.get("risk_summary") or "{}")
        item["checks_summary"] = json.loads(item.get("checks_summary") or "{}")
        results.append(item)

    conn.close()
    return results


def get_assessment_by_id(assessment_id: int, db_path: str = DB_FILE) -> Optional[Dict[str, Any]]:
    """Retrieve detailed assessment, including findings, threats, and mitigations."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM assessments WHERE id = ?", (assessment_id,))
    assessment_row = cursor.fetchone()
    if not assessment_row:
        conn.close()
        return None

    data = dict(assessment_row)
    data["risk_summary"] = json.loads(data.get("risk_summary") or "{}")
    data["checks_summary"] = json.loads(data.get("checks_summary") or "{}")
    data["raw_results"] = json.loads(data.get("raw_results") or "{}")

    # Get findings
    cursor.execute("SELECT * FROM findings WHERE assessment_id = ? ORDER BY id ASC", (assessment_id,))
    data["findings"] = [dict(r) for r in cursor.fetchall()]

    # Get threat scenarios
    cursor.execute("SELECT * FROM threat_scenarios WHERE assessment_id = ? ORDER BY risk_score DESC, id ASC", (assessment_id,))
    data["threat_scenarios"] = [dict(r) for r in cursor.fetchall()]

    # Get mitigation status
    cursor.execute("SELECT * FROM mitigation_status WHERE assessment_id = ?", (assessment_id,))
    data["mitigation_statuses"] = {r["threat_id"]: dict(r) for r in cursor.fetchall()}

    conn.close()
    return data


def delete_assessment(assessment_id: int, db_path: str = DB_FILE) -> bool:
    """Delete an assessment and its associated findings/threats."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM assessments WHERE id = ?", (assessment_id,))
    rows_affected = cursor.rowcount
    conn.commit()
    conn.close()
    return rows_affected > 0


def update_threat_risk(threat_id: str, assessment_id: int, likelihood: int, impact: int, db_path: str = DB_FILE) -> Dict[str, Any]:
    """Update likelihood, impact, and recalculated risk score for a threat scenario."""
    likelihood = max(1, min(5, int(likelihood)))
    impact = max(1, min(5, int(impact)))
    risk_score = likelihood * impact
    severity = calculate_severity(risk_score)

    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE threat_scenarios
        SET likelihood = ?, impact = ?, risk_score = ?, severity = ?
        WHERE threat_id = ? AND assessment_id = ?
    """, (likelihood, impact, risk_score, severity, threat_id, assessment_id))

    # Recalculate summary in assessments table
    cursor.execute("""
        SELECT severity, COUNT(*) as count
        FROM threat_scenarios
        WHERE assessment_id = ?
        GROUP BY severity
    """, (assessment_id,))

    counts = {r["severity"].lower(): r["count"] for r in cursor.fetchall()}
    risk_summary = {
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "total_threats": sum(counts.values())
    }

    cursor.execute("""
        UPDATE assessments
        SET risk_summary = ?
        WHERE id = ?
    """, (json.dumps(risk_summary), assessment_id))

    conn.commit()
    conn.close()

    return {
        "threat_id": threat_id,
        "likelihood": likelihood,
        "impact": impact,
        "risk_score": risk_score,
        "severity": severity,
        "risk_summary": risk_summary
    }


def update_mitigation_status(threat_id: str, assessment_id: int, status: str, notes: str = "", db_path: str = DB_FILE) -> bool:
    """Update the mitigation workflow status for a specific threat."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat() + "Z"

    cursor.execute("""
        INSERT INTO mitigation_status (assessment_id, threat_id, status, notes, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET status=excluded.status, notes=excluded.notes, updated_at=excluded.updated_at
    """, (assessment_id, threat_id, status, notes, now))

    # Fallback update in case row already exists for threat_id
    cursor.execute("""
        UPDATE mitigation_status
        SET status = ?, notes = ?, updated_at = ?
        WHERE assessment_id = ? AND threat_id = ?
    """, (status, notes, now, assessment_id, threat_id))

    conn.commit()
    conn.close()
    return True


def get_dashboard_metrics(db_path: str = DB_FILE) -> Dict[str, Any]:
    """Calculate aggregate statistics across all scans for the analytics dashboard."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM assessments")
    total_assessments = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM findings")
    total_findings = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM findings WHERE status = 'PASS'")
    checks_passed = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM findings WHERE status IN ('WARNING', 'FAIL')")
    checks_requiring_attention = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM threat_scenarios WHERE severity = 'Critical'")
    critical_threats = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM threat_scenarios WHERE severity = 'High'")
    high_threats = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM threat_scenarios WHERE severity = 'Medium'")
    medium_threats = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM threat_scenarios WHERE severity = 'Low'")
    low_threats = cursor.fetchone()[0]

    # STRIDE distribution
    cursor.execute("""
        SELECT threat_category, COUNT(*) as count
        FROM threat_scenarios
        GROUP BY threat_category
    """)
    stride_distribution = {r["threat_category"]: r["count"] for r in cursor.fetchall()}

    # Recent assessments
    cursor.execute("""
        SELECT id, target_url, hostname, scan_timestamp, overall_score, risk_summary
        FROM assessments
        ORDER BY id DESC LIMIT 5
    """)
    recent_rows = cursor.fetchall()
    recent_assessments = []
    for r in recent_rows:
        item = dict(r)
        item["risk_summary"] = json.loads(item.get("risk_summary") or "{}")
        recent_assessments.append(item)

    # Average score
    cursor.execute("SELECT AVG(overall_score) FROM assessments")
    avg_score_row = cursor.fetchone()[0]
    avg_score = round(avg_score_row, 1) if avg_score_row is not None else 0

    conn.close()

    return {
        "total_assessments": total_assessments,
        "total_findings": total_findings,
        "checks_passed": checks_passed,
        "checks_requiring_attention": checks_requiring_attention,
        "critical_threats": critical_threats,
        "high_threats": high_threats,
        "medium_threats": medium_threats,
        "low_threats": low_threats,
        "stride_distribution": stride_distribution,
        "recent_assessments": recent_assessments,
        "avg_security_score": avg_score
    }
