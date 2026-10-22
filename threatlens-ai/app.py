"""
ThreatLens AI - Website Security Risk Assessment Tool
Main Flask application routing and controller logic.
"""

import json
import os
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, Response
from database import (
    init_db,
    save_assessment,
    get_all_assessments,
    get_assessment_by_id,
    delete_assessment,
    update_threat_risk,
    update_mitigation_status,
    get_dashboard_metrics,
    calculate_severity,
    DB_FILE
)
from security_checks import (
    perform_website_assessment,
    validate_and_resolve_url,
    SSRFValidationError
)
from threat_model import (
    generate_threat_model,
    generate_executive_summary,
    calculate_risk
)
from sample_data import get_sample_assessment
from pdf_generator import generate_pdf_report

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "threatlens-ai-secret-key-educational-demo-2026")

# Initialize database tables on startup
init_db(DB_FILE)


@app.context_processor
def inject_global_data():
    """Inject app metadata and current year across all templates."""
    return {
        "app_name": "ThreatLens AI",
        "app_subtitle": "Website Security Risk Assessment & Threat Modeling Tool",
        "current_year": datetime.now(timezone.utc).year
    }


@app.route("/")
def index():
    """Homepage: URL input, sample profile buttons, security controls overview."""
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Execute passive website security assessment against an authorized target.
    Enforces anti-SSRF protections and passive non-intrusive checks.
    """
    raw_url = request.form.get("url", "").strip()
    if not raw_url:
        flash("Please enter a valid website URL to analyze.", "error")
        return redirect(url_for("index"))

    try:
        # 1. Run passive security assessment
        assessment_data = perform_website_assessment(raw_url)

        # 2. Generate STRIDE threat model
        threats = generate_threat_model(
            assessment_data["findings"],
            assessment_data["hostname"]
        )
        assessment_data["threat_scenarios"] = threats

        # 3. Calculate risk summary
        critical_count = sum(1 for t in threats if t["severity"] == "Critical")
        high_count = sum(1 for t in threats if t["severity"] == "High")
        medium_count = sum(1 for t in threats if t["severity"] == "Medium")
        low_count = sum(1 for t in threats if t["severity"] == "Low")

        assessment_data["risk_summary"] = {
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "total_threats": len(threats)
        }

        # 4. Generate executive summary
        assessment_data["executive_summary"] = generate_executive_summary(
            assessment_data["hostname"],
            assessment_data["overall_score"],
            threats,
            assessment_data["checks_summary"]
        )

        # 5. Persist in database
        assessment_id = save_assessment(assessment_data, DB_FILE)
        flash(f"Assessment completed successfully for {assessment_data['hostname']}.", "success")
        return redirect(url_for("results", assessment_id=assessment_id))

    except SSRFValidationError as e:
        flash(f"Security Alert (SSRF Protection): {str(e)}", "error")
        return redirect(url_for("index"))
    except ValueError as e:
        flash(f"Validation Error: {str(e)}", "error")
        return redirect(url_for("index"))
    except TimeoutError as e:
        flash(f"Connection Timeout: {str(e)} Target server took too long to respond.", "error")
        return redirect(url_for("index"))
    except Exception as e:
        flash(f"Assessment Error: An unexpected error occurred while assessing the target: {str(e)}", "error")
        return redirect(url_for("index"))


@app.route("/sample/<profile>")
def load_sample(profile: str):
    """
    Load a pre-configured sample assessment for instant offline demo or presentation.
    Valid profiles: 'vulnerable', 'moderate', 'hardened'.
    """
    if profile not in ("vulnerable", "moderate", "hardened"):
        profile = "vulnerable"

    sample_data = get_sample_assessment(profile)
    assessment_id = save_assessment(sample_data, DB_FILE)

    profile_names = {
        "vulnerable": "Insecure Legacy Web Portal",
        "moderate": "Moderate Campus Web Application",
        "hardened": "Hardened Defense-Lab Portal"
    }
    flash(f"Loaded sample demonstration scenario: '{profile_names.get(profile, profile)}'.", "info")
    return redirect(url_for("results", assessment_id=assessment_id))


@app.route("/dashboard")
def dashboard():
    """Analytics dashboard displaying aggregate security metrics, charts, and scan logs."""
    metrics = get_dashboard_metrics(DB_FILE)
    return render_template("dashboard.html", metrics=metrics)


@app.route("/results/<int:assessment_id>")
def results(assessment_id: int):
    """Display comprehensive scan results, findings table, and interactive STRIDE threats."""
    assessment = get_assessment_by_id(assessment_id, DB_FILE)
    if not assessment:
        flash("Assessment record not found.", "error")
        return redirect(url_for("history"))

    return render_template("results.html", assessment=assessment)


@app.route("/report/<int:assessment_id>")
def report(assessment_id: int):
    """Full executive security assessment report formatted for viewing and browser print."""
    assessment = get_assessment_by_id(assessment_id, DB_FILE)
    if not assessment:
        flash("Assessment record not found.", "error")
        return redirect(url_for("history"))

    return render_template("report.html", assessment=assessment)


@app.route("/report/<int:assessment_id>/export/json")
def export_json(assessment_id: int):
    """Export complete assessment data as structured JSON."""
    assessment = get_assessment_by_id(assessment_id, DB_FILE)
    if not assessment:
        return jsonify({"error": "Assessment not found"}), 404

    filename = f"threatlens-assessment-{assessment.get('hostname')}-{assessment_id}.json"
    response = Response(
        json.dumps(assessment, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )
    return response


@app.route("/report/<int:assessment_id>/export/pdf")
def export_pdf(assessment_id: int):
    """Generate and download a PDF assessment report using ReportLab."""
    assessment = get_assessment_by_id(assessment_id, DB_FILE)
    if not assessment:
        flash("Assessment record not found.", "error")
        return redirect(url_for("history"))

    try:
        pdf_stream = generate_pdf_report(assessment)
        filename = f"threatlens-report-{assessment.get('hostname')}-{assessment_id}.pdf"
        return send_file(
            pdf_stream,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        flash(f"PDF generation error: {str(e)}. You can also use the browser's Print feature (Ctrl+P / Save as PDF) from the report view.", "error")
        return redirect(url_for("report", assessment_id=assessment_id))


@app.route("/history")
def history():
    """List past assessments with search filter and pagination."""
    search_query = request.args.get("q", "").strip()
    assessments = get_all_assessments(limit=50, search=search_query, db_path=DB_FILE)
    return render_template("history.html", assessments=assessments, search_query=search_query)


@app.route("/assessment/<int:assessment_id>/delete", methods=["POST"])
def delete_assessment_route(assessment_id: int):
    """Delete an assessment and its associated findings and threats."""
    success = delete_assessment(assessment_id, DB_FILE)
    if success:
        flash("Assessment record was permanently deleted.", "success")
    else:
        flash("Failed to delete assessment record.", "error")
    return redirect(url_for("history"))


# ---------------- API Endpoints for Interactive Threat Model Adjustments ----------------

@app.route("/api/threat/<int:assessment_id>/<threat_id>/risk", methods=["POST"])
def api_update_threat_risk(assessment_id: int, threat_id: str):
    """
    Recalculate risk score immediately when a user adjusts Likelihood (1-5)
    and Impact (1-5) in the UI.
    """
    data = request.get_json() or {}
    likelihood = data.get("likelihood")
    impact = data.get("impact")

    if likelihood is None or impact is None:
        return jsonify({"error": "Missing likelihood or impact parameter"}), 400

    try:
        updated = update_threat_risk(threat_id, assessment_id, int(likelihood), int(impact), DB_FILE)
        return jsonify({
            "success": True,
            "data": updated
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/threat/<int:assessment_id>/<threat_id>/status", methods=["POST"])
def api_update_mitigation_status(assessment_id: int, threat_id: str):
    """Update mitigation workflow status (Open, In Progress, Mitigated, Accepted)."""
    data = request.get_json() or {}
    status = data.get("status", "Open")
    notes = data.get("notes", "")

    if status not in ("Open", "In Progress", "Mitigated", "Accepted"):
        return jsonify({"error": "Invalid status value"}), 400

    try:
        update_mitigation_status(threat_id, assessment_id, status, notes, DB_FILE)
        return jsonify({
            "success": True,
            "status": status,
            "notes": notes
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- Safe Error Handlers ----------------

@app.errorhandler(404)
def not_found_error(error):
    return render_template("index.html", error_message="The requested resource or page was not found."), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template("index.html", error_message="An internal application error occurred. No sensitive details exposed."), 500


if __name__ == "__main__":
    print("=" * 60)
    print(" ThreatLens AI — Website Security Risk Assessment Tool")
    print(" Running locally on http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=True)
