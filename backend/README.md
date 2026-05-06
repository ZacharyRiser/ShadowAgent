# Shadow Agent Backend

FastAPI prototype for the Shadow Agent gateway and purification engine.

## Run

```powershell
cd E:\SecurityTools\AIsec_Sandbox\CodeX\ShadowAgent\backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

## Smoke Test

```powershell
cd E:\SecurityTools\AIsec_Sandbox\CodeX\ShadowAgent\backend
python test_gateway.py
```
