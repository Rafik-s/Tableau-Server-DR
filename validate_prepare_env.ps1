Write-Host "Validating Modern Tableau DR Environment..." -ForegroundColor Cyan

# Check TSM installation
if (Get-Command tsm -ErrorAction SilentlyContinue) {
    Write-Host "[OK] TSM CLI detected." -ForegroundColor Green
} else {
    Write-Host "[ERROR] TSM CLI not found. Ensure Tableau Server bin directory is in PATH." -ForegroundColor Red
}

# Check AzCopy installation
if (Get-Command azcopy -ErrorAction SilentlyContinue) {
    Write-Host "[OK] AzCopy detected." -ForegroundColor Green
} else {
    Write-Host "[ERROR] AzCopy not found. Install AzCopy v10 to handle Azure transfers." -ForegroundColor Red
}

# Check Python environment
if (Get-Command python -ErrorAction SilentlyContinue) {
    Write-Host "[OK] Python environment detected." -ForegroundColor Green
} else {
    Write-Host "[ERROR] Python 3 not found." -ForegroundColor Red
}