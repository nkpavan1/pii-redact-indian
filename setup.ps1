#Requires -Version 5.1
<#
.SYNOPSIS
    One-time environment setup for pii-redact (Windows).

.DESCRIPTION
    Creates a local virtual environment, installs pii-redact and every
    Python dependency (Presidio, spaCy, PyMuPDF, openpyxl, pytesseract,
    cryptography, keyring, filelock, pytest), and downloads the spaCy NER
    model. This is the only step in this project that needs internet -
    everything downloaded here runs fully offline afterwards.

    Tesseract OCR is NOT installed by this script - it's a native binary,
    not a pip package. See the printed instructions at the end.

.PARAMETER SkipSpacyModel
    Skip the ~587MB en_core_web_lg download (e.g. if it's already cached
    or you only need the non-NER parts of the pipeline for now).

.EXAMPLE
    .\setup.ps1

.EXAMPLE
    .\setup.ps1 -SkipSpacyModel
#>

param(
    [switch]$SkipSpacyModel
)

$ErrorActionPreference = "Stop"

function Write-Step($message) {
    Write-Host ""
    Write-Host "==> $message" -ForegroundColor Cyan
}

Write-Step "Checking for Python"
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "Python was not found on PATH. Install Python 3.10+ first." -ForegroundColor Red
    exit 1
}
python --version

Write-Step "Creating virtual environment (.venv)"
if (Test-Path ".venv") {
    Write-Host ".venv already exists - reusing it."
} else {
    python -m venv .venv
}

$venvPython = ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Host "Virtual environment creation failed - $venvPython not found." -ForegroundColor Red
    exit 1
}

Write-Step "Upgrading pip"
& $venvPython -m pip install --upgrade pip

Write-Step "Installing pii-redact and all Python dependencies (editable install)"
& $venvPython -m pip install -e ".[dev]"

if (-not $SkipSpacyModel) {
    Write-Step "Downloading spaCy NER model (en_core_web_lg, ~587MB)"
    & $venvPython -m spacy download en_core_web_lg
} else {
    Write-Host ""
    Write-Host "Skipped spaCy model download (-SkipSpacyModel). PII detection will not" -ForegroundColor Yellow
    Write-Host "work until you run: .venv\Scripts\python.exe -m spacy download en_core_web_lg" -ForegroundColor Yellow
}

Write-Step "Python setup complete"
Write-Host ""
Write-Host "One manual step remains: Tesseract OCR (a native binary, not a pip package)." -ForegroundColor Yellow
Write-Host "Needed for scanned PDF pages and JPEG/PNG ID-card scans; everything else" -ForegroundColor Yellow
Write-Host "(CSV/JSON/XLSX and native-text PDF) works without it." -ForegroundColor Yellow
Write-Host ""
Write-Host "  1. Download the installer: https://github.com/UB-Mannheim/tesseract/wiki"
Write-Host "  2. Run it, then either add its install folder to PATH, or set"
Write-Host "     pytesseract.pytesseract.tesseract_cmd to the full path of tesseract.exe."
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Green
Write-Host "  .venv\Scripts\Activate.ps1        # activate the environment"
Write-Host "  pytest                            # run the test suite"
Write-Host "  redact --help                     # see CLI usage"
