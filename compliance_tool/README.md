# Compliance Analyzer (Phase 2)

Desktop application to compare requirement IDs in Word documents against test procedure references, with project-based persistence.

## Features
- Project-based save/load (`.compliance` JSON files)
- No database; nothing auto-saved
- Upload and store requirement documents (.docx)
- Upload and store test procedure documents (.docx)
- Parse system requirement IDs under Acceptance Criteria sections
- Link system requirements to stakeholder requirements when present
- Parse test steps and references from Word tables (TS / Ref.)
- Compliance analysis, orphan test references, and summary
- Export analysis to CSV

## Setup
```powershell
pip install -r requirements.txt
```

## Run
```powershell
python main.py
```

## Workflow
1. New Project
2. Add requirement documents
3. Add test procedure documents
4. Run Analysis
5. Save Project (`.compliance`)

## Notes
- Documents are copied into `documents/requirements/` and `documents/test_procedures/`.
- Saving is manual only; closing with unsaved changes will prompt you.

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
      project_manager.py
      exporter.py
      models.py
    utils/
      logger.py
```
