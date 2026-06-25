# SPECTRAL-RECON-TOOLKIT-v1.0

Usage:
# Full recon
python recon_toolkit.py --target http://example.com --recon
# Port scan custom range
python recon_toolkit.py --target http://example.com --portscan --ports 1-1024
# SQLi on parameterized URL
python recon_toolkit.py --target "http://example.com/page?id=1&user=test" --sqli
# Go nuclear — run everything
python recon_toolkit.py --target http://example.com --full
# Export results
python recon_toolkit.py --target http://example.com --full --output results.json
