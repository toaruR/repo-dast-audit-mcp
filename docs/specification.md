<!-- spec-doc:last-reviewed-commit=5aec27513fe0f01e1b9232fa0a367d335e5d2148 reviewed-at=2026-10-08 -->

# 仕様書

<!--
このファイルは /spec-doc コマンドが git 差分から自動で追記・更新する。
- 先頭のマーカー行は /spec-doc が「前回どのコミットまで確認したか」を記録するためのもの。
  手で編集しない（初回はマーカーなしのままでもよく、その場合 /spec-doc が初回モードで動く）
- 構成: 対象（機能 / モジュール / API / 設定 など）ごとに節を分ける
- 実装手順ではなく「何が・どう振る舞うか」（仕様・挙動・設計意図）を書く
-->

## 対象と確認範囲

`repo-dast-audit-mcp` は、ローカル Git リポジトリの追跡ファイルを静的に調べ、JSON と Markdown のレポートを返す MCP stdio サーバーである。

初回確認の対象はルートリポジトリの初期コミット `5aec27513fe0f01e1b9232fa0a367d335e5d2148`（1コミット、38ファイル）。本書はこのコミットの実装の挙動を記録する。設計書の要求がすべて実装済みであることを示すものではない。

関連文書:

- [起動・MCP登録手順](../README.md)
- [Repository Audit MCP 設計](design-repository-audit-mcp.md)
- [Repository Vulnerability Report MCP 設計（旧名, 現 repo-dast-audit-mcp）](design-repository-vulnerability-report-mcp.md)
- [実装計画](plans/repository-vulnerability-report-mcp.json)

## 対象範囲と実行環境

- 検査対象は Git index に登録されたファイルの現在の working tree 内容。未追跡・ignored ファイル、Git 履歴、リモート clone は検査しない。
- 対象コード、ビルド、テスト、パッケージマネージャー、外部 scanner を起動する機能はない。対象リポジトリへレポートを書き込まない。
- Python の AST、秘密情報に似た文字列、Python/npm の依存ファイルを扱う。検出は限定的な静的ルールによる候補であり、脆弱性の不存在や安全性を保証しない。
- 実行時依存ライブラリはなく、CPython 3.12 と既存の Git CLI を使用する。CPython 以外、または Python の major/minor が 3.12 以外なら起動を拒否する。
- `pyproject.toml` のパッケージ名は `repo-dast-audit-mcp`、バージョンは `0.1.0`。起動モジュールは `repo_dast_audit_mcp.server`。
- 開発用 `.venv/` は Git 管理対象から除外する。`tools/bootstrap-python.ps1` は `.venv` の作成・検証と、`src` を参照する `.pth` の作成を行う。
- bootstrap は bundled Python の特定の絶対パスを既定値・許可値として固定している。`-PythonPath` に任意の CPython を指定できる構成ではない。README の `/path/to/...` は表示用の例であり、別環境への移植にはスクリプトのパス設定の見直しが必要。

## MCP 通信と公開 API

### 通信形式

stdin/stdout は UTF-8 の改行区切り JSON-RPC 2.0。stdout にプロトコル応答を出力し、EOF で終了する。対応メソッドは `initialize`、`ping`、`tools/list`、`tools/call` と取消通知 `notifications/cancelled`。

実装の protocolVersion は `2024-11-05`。クライアントが別のバージョンを提示しても、このバージョンを応答する。`initialize` の応答は serverInfo の名前・バージョンと `capabilities: {"tools": {}}` を含む。初期化済みかどうかを追跡してツール呼出しを制限する機構はない。

通常の通知には応答しない。取消通知は `requestId` を記録し、対応する `tools/call` に取消状態を渡す。永続スキャンの取消は公開ツール `cancel_scan` が担当する。

JSON-RPC エラーは parse error `-32700`、invalid request `-32600`、method not found `-32601`、invalid params `-32602`。過大フレームは `-32000` / `E_FRAME_LIMIT` とし、同じ行の残りを読み捨てて次のフレームへ進む。

### ツール

入力 schema は Draft 2020-12、追加プロパティを拒否する。`root` は非空かつ最大32,767文字、`scan_id` は UUID として解釈できる文字列。

| ツール | 入力 | 挙動 |
| --- | --- | --- |
| `scan_repository` | 必須 `root: string`、任意 `dependency_advisories: boolean = false` | 対象を検証し、初期レポートを永続化した後、ワーカースレッドを開始する |
| `get_scan` | 必須 `scan_id: string` | 保存済みの最新世代の状態と、その世代にあるレポートを返す |
| `cancel_scan` | 必須 `scan_id: string` | 初回の取消要求を永続化する。重複要求・終端状態への要求は状態を変更しない |

成功結果は `content` の JSON 文字列と、同じ内容の `structuredContent` を含む。その内容は `ok: true`、`scan_id`、`state`、`revision`、`report`、`markdown`。レポートがない世代では `report` は `null`、`markdown` は空文字列となる。

ツール実行エラーは `isError: true` と `ok: false`、`code`、`message` を返す。代表的な code は `E_ROOT`、`E_NOT_GIT`、`E_GIT_UNAVAILABLE`、`E_INVENTORY`、`E_BUSY`、`E_CANCELLED`、`E_NOT_FOUND`、`E_STORAGE`、`E_SUPERVISION`。schema 違反・未知のツールは JSON-RPC の invalid params となる。

`dependency_advisories` が有効になるには、呼出し側の指定とサーバー側 `ServerConfig.dependency_advisories` の両方が `true` である必要がある。通常の起動設定は後者が `false` で、公開ツールからサーバーの設定・Git 実行ファイル・外部送信先を変更できない。

## 対象検証と Git inventory

- `root` は存在するディレクトリの絶対パスとし、`..`、symlink、Windows reparse point を通過するパスを拒否する。正規化後のパスと指定パスの同一性を検査する。
- `root` は Git top-level と一致しなければならない。サーバーの cache を内部に含む対象は拒否する。
- Git は `shell=False`、stdin 無効、固定 argv で起動する。`rev-parse --show-toplevel`、`rev-parse HEAD`、`ls-files -z --cached` を使用し、各呼出しに既定3秒の timeout を設ける。
- 環境の `GIT_*` を除去し、system/global Git 設定を無効化する。`--no-optional-locks` と `core.fsmonitor=false`、検証対象のパスだけを許可する一時的な `safe.directory` 設定を使う。
- HEAD がまだないリポジトリでは `head: null` を保持する。空の追跡一覧は `EMPTY_INVENTORY` として記録し、未検査の理由を残す。
- NUL 区切りの inventory を厳密に UTF-8 decode し、不正な相対パスを除外する。有効パスは重複除去後、UTF-8 byte 順に並べる。ファイル数上限を超える場合は一覧を切り詰め、`FILE_LIMIT` を記録する。
- 読取り時は containment、最終パスの reparse 属性、open 前後のファイル identity と size/mtime を比較する。競合を完全に排除する snapshot 保証はない。
- 大きいファイル、NUL を含む binary、UTF-8 として読めないファイル、読取り不能・変更検出されたファイルは未検査理由を残す。

## 検査ルールと依存アドバイザリ

### Python AST と秘密情報

| ルール | 検出候補 | severity |
| --- | --- | --- |
| `PY001` | `eval` / `exec` と、名前が `.eval` / `.exec` で終わる呼出し | `high` |
| `PY002` | `pickle.load` / `pickle.loads` | `high` |
| `PY003` | `yaml.load` | `high` |
| `PY004` | `subprocess` 系呼出しの literal `shell=True` | `high` |
| `SECRET001` | PEM private-key header | `critical` |
| `SECRET002` | token / secret / password / api-key を含む所定のキーへの単行代入 | `medium` |

AST は呼出し名の文字列表現を判定する。import alias や変数の再代入、入力値の到達経路を解析しない。`yaml.load` について SafeLoader の指定を判別せず、秘密情報の単行代入ではプレースホルダを除外しないため、誤検知を含み得る。

AST 入力の byte、depth、node 数を検査し、parse 失敗・上限超過は `partial` とする。解析結果は相対パス・位置・rule・severity と固定または秘匿した evidence を返し、秘密値や PEM body を保持しない。

### 依存ファイル

- `requirements.txt` 末尾に一致する追跡パスでは、コメントを除去して `name==version` の exact pin を抽出する。editable、URL/VCS、marker、非 exact 指定は未検査理由を残す。
- `package-lock.json` 末尾に一致する追跡パスでは JSON の `lockfileVersion` が整数であることを確認し、`packages`、なければ `dependencies` の直下を調べる。バージョン形式の拒否は限定的で、lock version や推移依存を完全に解決する機能ではない。
- OSV 無効時は `skipped` / `DISABLED`。exact package がない場合は `NO_EXACT_PACKAGES`、request 上限超過は `REQUEST_LIMIT`。
- 有効時は固定 HTTPS endpoint `https://api.osv.dev/v1/query` に ecosystem/name/version のみを POST する。TLS の標準検証を使い、redirect を拒否する。
- 応答の advisory ID を検出し、severity は `unknown`。network error は `offline` / `NETWORK_UNAVAILABLE`、不正応答は `error` / `MALFORMED_RESPONSE`、response サイズ超過は `partial` / `RESPONSE_LIMIT`。
- 既定起動での外部送信は無効。無効・offline・error は advisory 不在の確認として扱わない。

## スキャン状態と永続化

状態は `queued`、`running`、`completed`、`partial`、`cancelled`、`interrupted`、`failed`。`queued` から `running` または終端状態へ、`running` から終端状態へ遷移する。終端状態の新しい状態改訂は拒否する。

scan ID はサーバー生成の UUID4。状態改訂ごとに整数 `revision` を増やし、時刻は UTC の文字列で保持する。進捗は `files_total`、`files_completed`、`bytes_limit`、`bytes_read`、`analyzers_completed`、`findings_emitted`、整数 `progress_percent`。割合は `files_completed * 100 // files_total` で、対象0件なら100。

1プロセスで同時に許可する scan は1件。待ち行列はなく、別 scan が active の間は `E_BUSY`。検証と初期保存の後に daemon thread で実行する。ファイルごとに取消要求と経過時間を確認し、上限超過は `partial` / `TIMEOUT`、通常のワーカー例外は `failed` / `WORKER_FAILURE`。

cache の既定値は `%LOCALAPPDATA%/repo-dast-audit-mcp`。環境変数がなければホーム配下の `AppData/Local/repo-dast-audit-mcp` を使用する。

保存構造:

```text
cache/
  .root-hmac-key
  records/<scan_id>/
    current.json
    generations/<revision>/
      state.json
      report.json   # レポートを保存する世代にのみ存在
      report.md     # report.json と対で保存
```

一時ファイルへ書込み、flush/fsync 後に `os.replace` する。世代を書き終えた後に `current.json` を公開する。JSON/Markdown は同時に提供する必要があり、終端世代にはレポートを要求する。

raw root は状態に保存せず、cache の鍵で HMAC-SHA256 fingerprint を作る。状態には直前 audit HMAC を含め、pointer と状態の HMAC、JSON レポートの SHA256 を読取り時に検査する。破損レコードは `quarantine-<scan_id>` へ証拠をコピーし、元 ID の読取りは `E_STORAGE` として残す。

起動時に既存 active レコードを `interrupted` / `PROCESS_RESTART` に改訂する。ただし、保存済みレポートがある場合はその内容をそのまま再利用するため、復旧後の状態とレポートの state/revision が一致するとは限らない。

## JSON / Markdown レポート

canonical JSON のトップレベルは次の12項目。

```text
schema_version, scan_id, revision, state, head, limits, progress,
checks, findings, uncertainty, notice
```

JSON は UTF-8、キー順を固定し、不要な空白を付けずに serialize する。`checks` は analyzer ID/version/provenance 順、`findings` は severity・path・位置・ID 順に並べる。finding ID は analyzer・rule・path・位置・evidence に基づく SHA256 の先頭24文字。重複は `occurrences` にまとめる。

absolute path、PEM、credential 代入、URL credentials を秘匿し、evidence excerpt は既定160文字以内とする。`uncertainty` は analyzer の `partial`、`skipped`、`offline`、`error` 等や省略理由を保持する。

Markdown は canonical JSON だけから作り、Findings、Coverage、Uncertainty、Notice を表示する。HEAD 不在は `unborn/missing`。repository 由来の文字列に含まれる HTML、表区切り、backtick、角括弧等を escape する。

finding 上限・JSON byte 上限では finding を省略し、理由を uncertainty に記録する。Markdown 上限では切り詰めたことを本文に明記する。必須部分や省略表示も収まらない場合は例外となる。

## 資源上限の設定値と適用範囲

`Limits` の値は整数・既定値以下の所定範囲とし、不正値を補正せず設定エラーにする。MCP 入力から変更できない。下表は既定値であり、すべての処理に対する強制停止の保証ではない。

| 対象 | 既定上限 | 現在の適用範囲 |
| --- | --- | --- |
| JSON-RPC frame | 2 MiB | 改行単位のサイズ検査と過大行の読捨て |
| Git inventory | 2 MiB / 5,000ファイル | Git 出力取得後の検査と一覧の切詰め |
| ファイル読取り | 1 MiB / 累計50 MiB | 1ファイル上限は適用。累計上限は読取り停止に未接続 |
| scan / Git 呼出し | 60秒 / 3秒 | scan は検証後のファイル間で確認。Git は subprocess timeout |
| AST | 256 KiB / depth 100 / 50,000 nodes / 2秒 | byte/depth/node 数を検査。2秒の強制停止は未実装 |
| finding / JSON / Markdown | 1,000件 / 2 MiB / 1.5 MiB | 省略または明示的な出力切詰め |
| OSV | 100 requests / 応答1 MiB / hop 5秒 / 5 pages | manifest ごとの request 数、応答サイズ、hop timeout。pagination 未実装 |
| 保存 / 取消 | 100 records / 7日 / 取消6秒 / kill猶予1秒 | 設定値は存在するが retention・期限内取消・kill 管理は未実装 |
| 同時実行 | active scan 1 / queue 0 / client 1 | scan は1プロセス内で制御。プロセス間排他は未実装 |

## 要確認事項と検証状況

以下は確認済み実装と設計要求の差、および追加検証が必要な点。今回の仕様更新ではコードを変更しない。

1. **出力 schema の不整合**: 宣言された `outputSchema.report` は `additionalProperties: false` だが、実レポートの `revision` と `uncertainty` を定義していない。また、レポートなし世代の `report: null` と、一部の `cancel_scan` 応答の active state も宣言と一致しない。
2. **世代とレポートの対応**: running への改訂はレポートを保存せず、`get_scan` が `null` を返す期間がある。取消要求・再起動復旧では旧レポートを再利用する。最新 state/revision と JSON/Markdown の対応を要確認。
3. **上限の実効性**: 累計読取り byte、AST 時間、scan 全体の deadline、OSV 総 request 数・pagination、record retention、プロセス間排他、cache ACL の強制は設計要求どおりに実装されていない。AST はサーバープロセス内で解析する。
4. **取消と進捗**: 取消 latency は実装上0として記録され、実測値ではない。`findings_emitted` は終端でも0を設定するため、実際の finding 件数として使用できない。
5. **OSV とレポート**: 通常起動で OSV を有効にする公開設定手段はない。標準 urllib opener は環境 proxy を明示的に無効化していない。取得した advisory/package 情報を canonical finding に保持する仕様との整合を要確認。
6. **可搬性と自己検査テスト**: bootstrap は特定の bundled runtime path に依存し、自己検査テストは `.venv/Scripts/python.exe`、HEAD 不在、追跡一覧なしを前提にする。初回コミット後の現リポジトリではこのテスト前提が成立しない。

2026-10-08、対象コミットの checkout で次を実行した。

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests
```

結果は **40件中39件合格、1件失敗**。`tests/test_self_scan.py:57` の `report["head"] is None` の期待に対し、実際には対象コミットの HEAD hash が返る。後続の `partial` / `EMPTY_INVENTORY` の期待も現在の追跡一覧とは一致しない。その他の単体・stdio fixture テストの成功を、すべての設計要求・攻撃条件を満たした証明とは扱わない。
