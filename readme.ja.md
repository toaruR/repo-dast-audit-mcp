# repo-dast-audit-mcp

[English](README.md) | [日本語](readme.ja.md)

> **開発状況: プロトタイプ。** 本プロジェクトは実験的なプロトタイプです。インターフェース、保存形式、監査の動作は予告なく変更される可能性があります。本番利用は想定していません。

ローカルのWebアプリケーションをブラウザで動的にセキュリティ監査するMCPサーバーです。LLMクライアントがコードとブラウザの観測結果を読み、検査案を作成します。サーバーは、操作者が登録した判定基準に従って、分離されたDocker/Chromium環境で検証します。結果には再現手順、証拠のハッシュ、JSON/Markdownレポートを含みます。

読取り専用の静的リポジトリスキャンも利用できます。ブラウザ監査は、監査対象のプロジェクトごとに明示的に有効化します。

## ブラウザセキュリティ監査

ブラウザ監査には、観測、ソース参照、検査案の登録、検証、証拠取得、後片付けを行う9つのMCPツールがあります。サーバー自体はLLM APIを呼び出しません。接続したMCPクライアントが検査案を作成します。

### 検証できる項目

| 検査項目 | 検証方法 |
| --- | --- |
| 認可によるアクセス分離 | 所有者による正常なリソース読取りと、権限のない利用者による同じリソースの読取りを比較します。 |
| 反射型XSS | 正常な入力と登録済みのnonceプローブを比較し、Chromium上での実行を観測します。 |
| 業務上の制約 | 正常な入力と検査用に変更した入力を比較し、価格の下限など、登録された数値制約を確認します。 |

各検証は、新しい対象アプリ・ブラウザ環境で2回実行します。結果が一致すれば `confirmed` または `rejected`、結果が不一致または証拠が不十分なら `inconclusive` になります。登録済みの判定基準（oracle）がない検査案は `candidate` として残ります。

標準のセットアップでは、上記3項目を検証する合成の参照アプリ `fixture_vulnerable` と `fixture_patched` を登録します。**これらの検出結果は動作確認用であり、あなたのリポジトリの脆弱性ではありません。** 自分のサービスを監査する場合は、後述のプロジェクト専用プロファイルを登録してください。

### クイックスタート: 参照アプリ

必要な環境は、CPython 3.12、Linuxコンテナを実行できるDocker、Node.js/npmです。以下は、このMCPサーバーのリポジトリ直下で実行します。

1. 同梱ランタイム用の補助スクリプトで、ローカルのPython環境を作成・確認します。スクリプトに設定された同梱CPython 3.12ランタイムがインストールされている必要があります。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\bootstrap-python.ps1 -Create
```

2. 指定バージョンのPlaywright Coreをインストールし、ブラウザ実行環境と参照プロファイルを準備します。

```powershell
npm install --prefix .web-audit-runtime/node-runtime --ignore-scripts --save-exact playwright-core@1.62.1

$browserCore = (Resolve-Path .web-audit-runtime/node-runtime/node_modules/playwright-core).Path
.\.venv\Scripts\python.exe -m repo_dast_audit_mcp.web_audit.setup --root (Get-Location).Path --playwright-core $browserCore
```

セットアップは、固定された公式Playwright Dockerイメージとseccompプロファイルをダウンロードし、専用のworkerイメージを作成します。生成物はGit対象外の `.web-audit-runtime/` に保存します。環境の準備は操作者が行う作業であり、MCPツールでは実行しません。

3. ブラウザ監査を有効化してstdioサーバーを起動します。または、次の登録例でMCPクライアントを設定します。

```powershell
$env:REPO_DAST_AUDIT = '1'
$env:REPO_DAST_PROFILES = (Resolve-Path .web-audit-runtime/profiles.json).Path
.\.venv\Scripts\python.exe -m repo_dast_audit_mcp.server
```

サーバーは、改行区切りのJSON-RPCをstdioで扱い、標準出力にはプロトコルの応答だけを書き出します。レポートと監査記録は、リポジトリ外の `%LOCALAPPDATA%\repo-dast-audit-mcp` に保存します。

### 監査対象プロジェクトへのMCP登録

ブラウザプロファイルは、対象リポジトリのルートに紐付きます。監査対象プロジェクトの `.mcp.json` に、ブラウザ監査を有効化した設定を追加してください。サーバーのPython環境と対象プロジェクトのプロファイル登録ファイルには、どちらも絶対パスを指定します。

```json
{
  "mcpServers": {
    "repo-dast-audit": {
      "type": "stdio",
      "command": "/path/to/repo-dast-audit-mcp/.venv/Scripts/python.exe",
      "args": ["-m", "repo_dast_audit_mcp.server"],
      "env": {
        "PYTHONUTF8": "1",
        "REPO_DAST_AUDIT": "1",
        "REPO_DAST_PROFILES": "/path/to/audited-project/.web-audit-runtime/profiles.json"
      }
    }
  }
}
```

参照アプリのクイックスタートでは、このMCPサーバーのリポジトリ内に生成した登録ファイルを使用します。自分のサービスでは、次の手順で対象リポジトリ用に生成した登録ファイルを使用します。

登録後はクライアントを再起動または再接続し、`tools/list` に静的スキャンの3ツールとブラウザ監査の9ツールが表示されることを確認してください。登録しても、実行中のチャットにツールが自動追加されるわけではありません。ブラウザ監査を有効化する設定はプロジェクト単位で登録します。グローバル登録を併用する場合は `REPO_DAST_AUDIT` を省略し、静的スキャンだけを公開してください。

### 自分のサービスを監査する

操作者が管理するJSONプロファイルを準備します。サービスの起動コマンド、必要に応じたコンテナイメージ、ポート、テストアカウント、リソースの所有者とアクセス権、操作対象、リクエストテンプレート、変更可能なフィールド、判定基準を定義してください。LLMやページの内容からプロファイルを生成・変更する構成ではありません。

このMCPサーバーのリポジトリ直下で、クイックスタートで取得したPlaywright Coreのパスを使い、対象プロジェクトの登録ファイルを生成します。

```powershell
.\.venv\Scripts\python.exe -m repo_dast_audit_mcp.web_audit.setup --root /path/to/audited-project --runtime-dir /path/to/audited-project/.web-audit-runtime --playwright-core $browserCore --project-profile /path/to/operator-profile.json
```

サービスは、Gitで追跡されたファイルの読取り専用スナップショットと、分離されたテストデータで起動できる必要があります。未追跡ファイル、仮想環境、秘密情報を含むファイルは自動転送しません。必要な依存関係はコンテナイメージに準備してください。監査中の依存関係のインストール、外部データベースへの接続、本番サービスへの接続は行いません。独自のイメージは不変のイメージIDで登録します。

実サービスを登録する前に、[プロファイルの例とセットアップの詳細](docs/web-security-audit.md#実プロジェクトの登録)を確認してください。

### クライアントの操作手順

| ツール | 用途 |
| --- | --- |
| `start_web_audit` | 登録済みのリポジトリ・プロファイルのスナップショットを作り、非同期で監査を開始します。 |
| `get_web_audit` | 状態、revision、観測結果、検査案、実行上限、レポート情報を取得します。 |
| `web_action` | 登録済みの利用者として観測し、相対パスへの移動、観測時に発行されたハンドルによる操作、登録済みリクエストの再送を行います。 |
| `get_web_source` | 秘密情報を除去したスナップショットのソースと公開プロファイルを参照します。 |
| `propose_web_case` | 観測結果とソースに基づく検査案を登録します。 |
| `verify_web_case` | 正常系と攻撃系の動作を、新しい環境で2回確認します。 |
| `get_web_artifact` | ハッシュ付きの証拠とJSON/Markdownレポートを取得します。 |
| `cancel_web_audit` | 中止と後片付けを要求します。 |
| `finish_web_audit` | 正常終了を要求し、後片付け後の結果を確認します。 |

1. 登録済みのルートとプロファイルで監査を開始し、`get_web_audit` を定期的に呼び出して準備完了と現在のrevisionを確認します。
2. `web_action` でサービスを観測します。観測結果の `source_ref` から公開プロファイルを読み、`get_web_source` で関連するスナップショットのコードを確認します。
3. 観測した動作と登録済みの判定基準に基づく検査案を作成し、`verify_web_case` で検証します。
4. 判定結果と証拠を取得して監査を終了し、後片付けを確認してから最終レポートを取得します。

状態を変更する操作には、現在のrevisionとUUID形式の `client_action_id` を指定します。利用者ごとの操作には `actor_id` も必要です。同じ操作IDと同じ入力で再試行すると、既存の処理結果を返します。同じIDで入力を変更すると拒否されます。書込み操作の応答を受け取れなかった場合は、監査状態を確認してから再試行方法を判断してください。

### 分離・証拠・制限

対象アプリは外部ネットワークへ接続できません。Chromiumは、対象アプリのネットワーク名前空間内にある固定のループバックプロキシを通じて通信します。対象アプリとworkerのコンテナは非rootで実行し、capabilityを除去し、no-new-privilegesと読取り専用のルートファイルシステムを使用します。ホストのbind mountやDocker socketへのアクセスはありません。移動先とリクエストは登録済みの範囲に制限し、任意のスクリプトを評価するMCPツールは提供しません。

レポートには、確認した検出結果、再現手順、検査範囲、資格情報を除去してから計算した証拠のハッシュを含みます。中断した監査はサーバーの再起動時に回収し、結果が不明な操作は `outcome_unknown` として記録します。後片付けを確認できない場合は、新しい監査を拒否します。

現在の検証対象は、上記3種類の登録済み判定基準と、単一リクエストの検査です。保存型XSS、CSRF、複数ステップの判定基準、任意の業務ロジック、外部サービス、スクリーンショット、プロファイルの自動生成、静的スキャンとのスナップショット連結には対応していません。検出結果から原因となったソースの行を特定するものではなく、サービス全体の安全性やLLMの検出率を保証するものでもありません。

プロファイルの定義、実行上限、復旧動作、検証コマンドは、[ブラウザ監査の詳細ガイド](docs/web-security-audit.md)を参照してください。

## 静的リポジトリスキャン

`scan_repository`、`get_scan`、`cancel_scan` で、Gitが追跡するファイルを調べ、正規化されたJSONとMarkdownのレポートを作成できます。静的スキャンは読取り専用で、DockerもPlaywrightも不要です。

静的スキャンだけを登録する場合は、上記と同じ `command` と `args` を使い、`env` には `PYTHONUTF8=1` だけを指定します。`REPO_DAST_AUDIT` と `REPO_DAST_PROFILES` は省略してください。`scan_repository` の `root` 引数で対象リポジトリを指定します。

## ライセンス

MIT。[LICENSE](LICENSE)を参照してください。

ブラウザ監査のセットアップでは、Playwright Core、公式Playwright Dockerイメージ、seccompプロファイル（Apache-2.0）をダウンロードします。これらをこのリポジトリで再配布しているわけではありません。作成したworkerイメージを配布する場合は、それぞれのライセンス表記を保持してください。
