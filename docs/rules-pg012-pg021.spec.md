# promptguard 第二批規則（PG012～PG021 與擴充）SPEC

- 日期：2026-10-24
- 意圖：promptguard 目前抓不到 Cloudflare security-audit-skill 缺口清單裡多項靜態可偵測的危險寫法（萬用核准、CI 權限過寬、驗證被停用、依賴來源不安全等），使用者掃 MCP／agent 設定與 CI 檔時會漏報。
- 使用者原話：「1B2A3A4A5B6A」（Victor，2026-10-24 10:06，回覆 Claude 列的選項）。所選選項的文字由 Claude 擬，摘要如下：
  - 1B：PG003 的豁免改法和 PG022 不做，其餘都做（PG003 的詞表擴充照做）。
  - 2A：分 3 批依序做；原型同時做，雲端工作階段等前一批合併後再開下一批。
  - 3A：明確可被利用的給 high、要特定情境才危險的給 medium；原型做完先給 Victor 看對照表再開 PR；既有規則擴充維持原本嚴重度。
  - 4A：全部合併後發一次 v1.1.0，最後一個 PR 把 `__version__` 和 pyproject 改成 1.1.0。
  - 5B：掃描範圍只加設定檔 .env、Dockerfile、.npmrc，放第 3 批。
  - 6A：spec 進 repo `docs/`。
- 必須做到：
  1. 第 1 批新規則：PG012、PG015、PG016、PG017、PG018、PG019、PG020。
  2. 第 2 批新規則：PG013、PG014、PG021。
  3. 第 3 批擴充：PG002 角色標記、PG003 占位符詞表、PG007 秘密格式；scanner 納入 .env、.env.*、Dockerfile、Dockerfile.*、*.dockerfile、.npmrc；版本號改 1.1.0。
  4. 每條新規則／每項擴充至少 2 個要觸發、2 個不該觸發的測試（含易誤報情境），另加 400 KB 單行效能測試（2 秒內）。
  5. README「What it catches」表補列或更新，README 自掃告警數不增加。
  6. 掃 repo 自身、examples、README 的告警數變化逐則可解釋。
  7. 三批依序開 PR，每批以當下最新 origin/main 為底；全部合併後發 v1.1.0 tag 與 release。
- 明確不做：PG022；PG003 的 delimiter 豁免改法；scanner 納入 .py／.js／.ts；改 examples/、.github/workflows/ci.yml、docs/gap-analysis 文件；新增第三方依賴；新增 Rule 型別或改 Finding、CLI、輸出格式；第 1、2 批改版本號。
- 不變量：既有 81 個測試不改期望值且全過；Python 3.8 可跑、只用標準函式庫（不用 tomllib）；`# promptguard:ignore` 對新規則有效；`examples/secure-agent.json` 仍為 OK、exit 0；沿用 `Rule(id, severity, description, detector)` 與 PG008 起的 `_file_level` 檔案層級快取慣例。
- 假設：
  - 嚴重度由原型提出建議值，Victor 看表確認後才開 PR。
  - PG019 的 `-k` 只在 curl 類命令內判斷。
  - PG007 對 .env.example／.sample／.template／.dist 與明顯占位值（your-key、xxx、changeme、<...>）不報。
  - 第 2、3 批原型以 56a1e1c 為底，和最終 PR 的底不同；告警數在前一批合併後重算。
  - 本 spec 在第 1 批 PR 一起加入 `docs/`。
- 驗收條件：
  1. 對應 1～3：每個 id 出現在 `RULES`，每條規則／擴充有對應的 TestCase 類別。
  2. `python -m unittest discover -s tests -v` 全過，測試數比該批之前多，且每條至少 5 個（4 正反＋1 效能）。
  3. 對 `promptguard/*.py` 執行 `ast.parse(src, feature_version=(3, 8))` 全部成功。
  4. `git diff --stat origin/main` 只含該批允許的檔案。
  5. 告警數（repo 自身／examples／README）前後差異逐則列出原因。
  6. acceptance.md 的刁鑽測資在 PR 分支上的結果與原型一致，或差異有合理說明。
  7. v1.1.0：`promptguard --version` 印 1.1.0，tag 指向合併後的 main。
