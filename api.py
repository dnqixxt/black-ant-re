from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from core.analyzer import SafeVectorAnalyzer
import os
import uuid
import tempfile

app = Flask(__name__)
# Limit maximum payload size to 50MB
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
UPLOAD_FOLDER = os.path.join(tempfile.gettempdir(), "formiga_uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/analyze', methods=['POST'])
def analyze_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
        
    safe_name = secure_filename(file.filename)
    unique_name = f"{uuid.uuid4().hex}_{safe_name}"
    filepath = os.path.join(UPLOAD_FOLDER, unique_name)
    
    file.save(filepath)
    
    try:
        analyzer = SafeVectorAnalyzer(filepath, interactive=False)
        analyzer.run_analysis()
        return jsonify(analyzer.results)
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500
    finally:
        # Cleanup uploaded sample post-triage
        if os.path.exists(filepath):
            os.remove(filepath)

if __name__ == '__main__':
    # Localhost binding for local triage integration
    app.run(host='127.0.0.1', port=5000)
