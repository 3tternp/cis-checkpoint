from flask import Flask, render_template, request, send_file, flash
from pathlib import Path
import tempfile, uuid, os
from .scanner import scan_archive
from .report import render_report
app=Flask(__name__); app.secret_key='change-this-for-production'
OUT=Path(tempfile.gettempdir())/'checkpoint_audit_reports'; OUT.mkdir(exist_ok=True)
@app.route('/',methods=['GET','POST'])
def index():
    if request.method=='POST':
        f=request.files.get('archive')
        if not f or not f.filename: flash('Select a .tgz, .tar.gz, or .tar archive.'); return render_template('index.html')
        suffix='.tar.gz' if f.filename.endswith('.tar.gz') else Path(f.filename).suffix
        src=OUT/f'{uuid.uuid4().hex}{suffix}'; f.save(src)
        try:
            meta, findings=scan_archive(str(src)); html=render_report(meta,findings)
            rid=uuid.uuid4().hex; out=OUT/f'{rid}.html'; out.write_text(html,encoding='utf-8')
            return render_template('results.html',meta=meta,findings=findings,report_id=rid)
        except Exception as e: flash(f'Scan failed: {e}')
        finally:
            try: src.unlink()
            except: pass
    return render_template('index.html')
@app.route('/report/<rid>')
def report(rid):
    p=OUT/f'{rid}.html'
    if not p.exists(): return 'Report not found',404
    return send_file(p,as_attachment=True,download_name='Check_Point_Configuration_Audit_Report.html')
def main(): app.run(host='127.0.0.1',port=5000)
