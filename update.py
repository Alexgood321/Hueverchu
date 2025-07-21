name: Update Configs

on:
  schedule:
    - cron: '0 * * * *'  # каждый час
  workflow_dispatch:     # запуск вручную

jobs:
  update:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.x'

      - name: Install dependencies
        run: pip install requests pyyaml

      - name: Run script
        run: |
          python update.py
          mkdir -p output
          mv shadowrocket.txt clash.yaml ping_debug.txt output/

      - name: Commit and push results
        run: |
          git config --global user.name 'github-actions'
          git config --global user.email 'github-actions@github.com'
          git add output/
          git commit -m "🤖 Автообновление конфигов" || echo "No changes to commit"
          git pull --rebase origin main || echo "Nothing to rebase"
          git push
