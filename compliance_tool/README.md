# Compliance Analyzer (Phase 1)

Minimal desktop application to compare requirement IDs in Word documents against test procedure references.

## Features
- Upload and store requirement documents (.docx)
- Upload and store test procedure documents (.docx)
- Parse system requirement IDs (BNC/DLS/NSE prefixes)
- Parse test steps and references from Word tables (TS / Ref.)
- Run compliance analysis and view coverage
- Manually save/load analysis results (no automatic persistence)

## Setup
```powershell
pip install -r requirements.txt
```

## Run
```powershell
python main.py
```

## Notes
- Documents are copied into `documents/requirements/` and `documents/test_procedures/`.
- Analysis results can be saved and re-opened manually from the UI. The app does not auto-save.

## Project Layout
```
compliance_tool/
  main.py
  requirements.txt
  README.md
  documents/
    requirements/
    test_procedures/
  src/
    ui/
      app_ui.py
      components.py
    backend/
      document_manager.py
      parser.py
      analysis_engine.py
      models.py
    utils/
      logger.py
```
