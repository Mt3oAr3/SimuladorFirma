# Demo de firma digital (SHA-256 + RSA-PSS + PKI)

Proyecto académico — Tema 4: Introducción a la criptografía.

## Instalación (una sola vez)

Windows (PowerShell):
    python -m venv .venv
    .venv\Scripts\Activate.ps1
    pip install -r requirements.txt

Linux / macOS:
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

Si PowerShell bloquea el script de activación:
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

## Uso

    streamlit run app.py          # app web en http://localhost:8501
    python demo_consola.py        # versión por consola (plan B)
    pytest -v                     # pruebas automáticas

## Estructura

    app.py            Interfaz (5 pestañas)
    crypto_core/      Lógica criptográfica (hash, claves, firma, PKI)
    tests/            Pruebas automáticas
    documentos/       Documentos de ejemplo
    salida/           Archivos generados por demo_consola.py
