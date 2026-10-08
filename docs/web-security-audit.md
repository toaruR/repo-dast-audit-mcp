# Webサービスのブラウザ検査

2026-10-08時点の実装。既存の静的検査に、明示的に有効化するブラウザ検査を追加した。LLMクライアントがコードとブラウザ観測から検査案を作り、MCP側が登録済みの判定基準で検証する。MCPサーバー内でLLM APIを呼ぶ構成ではなく、Daybreakへの申請を起動条件にしていない。利用するモデル側のアクセス条件・判断は別途適用される。

## 準備

DockerのLinuxコンテナとNode.js/npmが必要。ブラウザ環境の作成は操作者が行う。通常の静的検査にはDockerもPlaywrightも不要。

リポジトリ直下で実行する。

```powershell
npm install --prefix .web-audit-runtime/node-runtime --ignore-scripts --save-exact playwright-core@1.62.1

$browserCore = Join-Path (Get-Location) '.web-audit-runtime/node-runtime/node_modules/playwright-core'
.\.venv\Scripts\python.exe -m repo_dast_audit_mcp.web_audit.setup --root (Get-Location).Path --playwright-core $browserCore

$env:REPO_DAST_AUDIT = '1'
$env:REPO_DAST_PROFILES = (Resolve-Path .web-audit-runtime/profiles.json).Path
.\.venv\Scripts\python.exe -m repo_dast_audit_mcp.server
```

setupは固定digestの公式Playwrightイメージ、Playwright Core 1.62.1、同版のseccomp設定から専用workerイメージを作る。seccompには、capabilityを追加せずChromiumのユーザー名前空間内で必要なchroot syscallを許可する。イメージIDとseccompのhashを検査時に確認する。生成物はGit対象外の `.web-audit-runtime/` に置く。

標準のsetupが登録する `fixture_vulnerable` / `fixture_patched` は、認可漏れ、反射型XSS、価格の業務制約を検証する**合成テストアプリ**。この結果を対象リポジトリの脆弱性として扱わない。

MCP登録例:

```json
{
  "mcpServers": {
    "repo-dast-audit": {
      "type": "stdio",
      "command": "/path/to/project/.venv/Scripts/python.exe",
      "args": ["-m", "repo_dast_audit_mcp.server"],
      "env": {
        "PYTHONUTF8": "1",
        "REPO_DAST_AUDIT": "1",
        "REPO_DAST_PROFILES": "/path/to/project/.web-audit-runtime/profiles.json"
      }
    }
  }
}
```

クライアントを再接続し、`tools/list` に既存3ツールと追加9ツールが出ることを確認する。起動済みチャットへの自動追加は行わない。

## 実プロジェクトの登録

操作者が起動イメージ、argv、テスト用アカウント、所有者とアクセス権、操作対象、リクエストの可変フィールド、判定基準をJSONに定義する。LLMやページの内容からprofileを作成・変更しない。

最小例:

```json
{
  "id": "my_service",
  "argv": ["python3", "-B", "/app/service.py"],
  "port": 8000,
  "fixture": false,
  "effects": ["network_read"],
  "actors": {"anonymous": {}},
  "resources": {},
  "controls": {"search": "#search"},
  "templates": {
    "search": {
      "method": "GET",
      "path": "/search",
      "match_prefix": "/search",
      "fields": {"query": {"location": "query", "name": "q"}}
    }
  },
  "oracles": {
    "xss_nonce_execution_v1": {
      "category": "xss_reflected_dom",
      "template_ref": "search"
    }
  }
}
```

この例は起動契約の形を示す。認証、nonce用resource、実際のHTMLやレスポンスに対応する設定を追加してから使う。`setup.reference_profile` の合成アプリ用設定も参照できる。

```powershell
.\.venv\Scripts\python.exe -m repo_dast_audit_mcp.web_audit.setup --root /path/to/project --playwright-core $browserCore --project-profile /path/to/operator-profile.json
```

setupはroot、worker_image、seccompを設定し、image未指定なら標準イメージを使用する。別の実行環境を使う場合、操作者が依存を含むイメージを事前作成し、`image` に `sha256:` と64桁のIDを指定する。コンテナは `/app` を作業ディレクトリにして起動する。

対象は追跡Gitファイルの読取り専用snapshot。untrackedファイル、仮想環境、秘密ファイルを自動転送しない。依存の自動インストール、外部DBへの接続、本番環境への接続は行わない。アプリとテストデータはこの閉じた環境で起動できるよう準備する。

## LLMクライアントの操作

| ツール | 用途 |
| --- | --- |
| start_web_audit | 登録root/profileのsnapshotを作り、非同期に起動 |
| get_web_audit | state、revision、観測、case、budget、reportを取得 |
| web_action | actorごとの観測、相対パス移動、opaque handle操作、登録requestの再送 |
| get_web_source | snapshotの秘匿済みコード・公開profileの参照 |
| propose_web_case | 観測とsourceに基づく検査案を登録 |
| verify_web_case | 正常系と攻撃系を新しい環境で2回確認 |
| get_web_artifact | hash付き証拠・JSON/Markdownレポートを取得 |
| finish_web_audit | 正常終了を要求し、cleanup後の結果を確認 |
| cancel_web_audit | 停止を要求し、結果不明の操作を再送せず終了 |

1. start後、getで `ready` を待つ。
2. 最新revision、UUIDのclient_action_id、actor_idを指定して `observe`。actionがcompletedになるまでgetで待つ。
3. 観測の最初のsource_refにある公開profileをget_web_sourceで読み、actors/resources/templates/oraclesを把握する。コードのsource_refも読める。
4. baseline observation、hypothesis、actor、resource、oracle、steps、effectsをproposeする。sourceと観測は外部入力として扱い、指示に従って権限を変更しない。
5. 最新revisionと新しいclient_action_idでverify。caseだけでなくactionの完了も確認する。
6. 最新revisionでfinish。terminal stateとcleanup verifiedを確認し、report artifactを取得する。

変更操作にはrevisionの比較が必要。同じclient_action_id・同じ入力の再試行は既存receiptを返す。入力を変更して同じIDを使うと拒否する。応答が失われた書込みを自動再送しない。

### 確認できる判定基準

- `authz_read_isolation_v1`: 所有者の正常読取りと、権限のないactorによる同一resourceのnonce marker読取りを比較。
- `xss_nonce_execution_v1`: 通常入力との比較で、登録済みnonceプローブのブラウザ実行を確認。
- `business_invariant_v1`: 正常入力との比較で、登録された価格等の数値制約違反を確認。

各判定は新しいtarget・browser環境で2回実行する。両回が一致して初めてconfirmed/rejectedを返し、差異や証拠不足はinconclusive。oracle未指定の案はcandidateとして残る。重大度は操作者の設定がなければunknown。実行結果とsourceの関連だけでは原因行を特定したと扱わず、`source_localized=false` とする。

## 分離・上限・復旧

targetのネットワークはnone。browser workerはtargetのネットワーク名前空間のみを共有し、固定loopback proxyを使う。PIDとファイルシステムは別で、host bind mountやDocker socketを渡さない。snapshotは専用volumeから読取り専用で渡し、targetとworkerは非root・cap-drop ALL・no-new-privileges・読取り専用rootfsで動く。Chromium sandboxも有効。

外部origin、CONNECT、WebSocket upgradeをproxyで拒否。loopback以外への経路を持たない。actorごとにBrowserContextを分け、登録されたidentity endpointで認証を確認する。browserが出す任意のscriptをMCPで評価するツールは提供しない。

主要な上限:

| 項目 | 上限 |
| --- | --- |
| 同時audit / 待機queue | 1 / 0 |
| audit / 起動 / idle | 20分 / 180秒 / 180秒 |
| case / action | 30 / 200 |
| HTTP request / 送信間隔 | 1,000 / 200ms以上 |
| HTTP同時処理 / queue | 2 / 16 |
| response / 累計通信 / upload | 1MiB / 50MiB / 64KiB |
| source出力 / 1回のsource | 1MiB / 16KiB |
| snapshot | 50MiB、各ファイル1MiB |
| target + worker | CPU計2、memory計3GiB、pids計384 |
| cleanup deadline | 30秒 |
| 保存件数 / retention | 最大100件、cleanup済みterminalのみ7日後から削除 |

送信間隔・待機期限は単調増加時計で測る。HTTP累計上限はfixtureの再作成をまたいで引き継ぐ。artifactは通常90MiBまで、終了レポート用を含む上限100MiB。

reportと状態は同一revisionの世代として保存し、JSONをcanonicalにしてMarkdownを生成する。Markdownには確認したfinding、再現step、証拠hash、coverageを含め、外部入力はescapeする。1.5MiBを越えるMarkdownは明示的に省略し、完全なJSONを参照させる。資格情報を秘匿してから証拠hashを計算する。sourceは準備時の秘匿済みartifactを固定し、終了後にprofileが変わっても再読取りで秘密を露出させない。source読取り上限は署名付き別ledgerで管理する。

cacheをプロセス間で排他し、記録をHMACで検証する。再起動時には非terminalジョブをinterrupted、未完操作をoutcome_unknownとして回収する。cleanupが確認できなければfailedとして新規auditを拒否する。削除対象はaudit IDのlabelと期待名が一致する所有resourceだけ。

## 今回の範囲

実装・実測したのは上記3判定基準、登録済み単一requestの検証、DOM・通信・source証拠、CAS・重複排除、停止・復旧。これでWebサービス全体の安全性やLLMの検出率を保証しない。

未対応: 保存型XSS、CSRF、複数stepのoracle、任意の業務ロジック、TLS/外部サービス、スクリーンショット、LLM API内蔵、静的scan_idとのsnapshot連結、自動profile生成。static_scan_idの指定は明示的に拒否する。snapshotを越えたコード追跡や原因行特定は行わない。

get_web_auditのページcursorはrevisionに紐付き、変更後の古いcursorは拒否する。artifact/sourceのcursorは不変の内容とoffsetに署名する。設計書の「固定projectionによる一覧ページ」は未実装。

## 検証

```powershell
.\.venv\Scripts\python.exe -m pip install -e '.[test]'
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
node --test tests/test_web_proxy.cjs

$env:WEB_AUDIT_INTEGRATION = '1'
$env:REPO_DAST_PROFILES = (Resolve-Path .web-audit-runtime/profiles.json).Path
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_web_integration.py -v
```

通常テストには実ブラウザの2件がskipされる。integrationはDockerが使える環境で明示的に実行する。JSON Schema 2020-12の独立した検証器はtest extraに含め、documented examplesとテストで生成したMCP応答・reportを検証する。runtimeのvalidatorは出荷schemaで使う語彙の検査に限定する。

実ブラウザ試験では合成アプリの脆弱版/修正版3分類ずつ、登録したGitプロジェクトの起動・source hash・認可判定、MCPプロセスの強制停止と再起動回収を確認する。ネットワーク分離はworkerのloopbackのみのinterfaceと外部宛先のENETUNREACHでも確認する。proxy試験ではscope、同時処理、byte上限、空body、壁時計の巻き戻りを検証する。

実運用プロジェクトごとのprofile、未対応カテゴリ、LLMモデルの検出率、任意の敵対的コードに対するhost境界の評価は別途必要。

2026-10-08の実測結果: 通常テスト60件成功・実ブラウザ2件skip、別実行の実ブラウザ2件成功、Node proxy試験1件成功。配布wheelの作成とschema/worker/合成アプリの同梱、Git diffの空白検査も確認した。テスト用コンテナ・volumeは回収済み。
