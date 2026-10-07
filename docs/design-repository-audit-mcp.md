# Repository Audit MCP 設計

## 目的・境界

指定されたローカル Git repository を read-only で調査し、機械可読 JSON と同内容の Markdown を返す。対象コードの実行、ビルド、依存導入、外部 scanner の導入は行わない。Python 3.12 stdlib の AST、文字列ルール、Git tracked-file inventory が主機構。結果は限定的な静的観測であり、脆弱性なし／安全との保証を出さない。現 workspace は Git 管理外なので直接の初期検証は E_NOT_GIT。独立した temporary Git fixture で実 MCP 検証する。

MVP は単一ユーザーのローカル stdio server。Git CLI は inventory のみ（target hook/config/filter を実行しない）。Python、秘密鍵／設定、npm/PyPI exact-pin の optional OSV が範囲。動的解析、全言語 taint、推移依存解決、range 解決、Git履歴、remote clone は範囲外。使用者は `coverage` と各 check の理由を見て未検査を判断する。

## 配置・実行・責任

想定実装は `src/repository_audit_mcp/{server,store,inventory,rules,dependencies,report}.py`。server は framing/validation/FSM、store は durable state、inventory は root/path/byte 制限、rules は pure bounded analysis、dependencies は OSV、report は二形式の同一データ rendering を担う。設計段階ではこれらを実装しない。

実装する manifest の全内容:

```toml
[build-system]
requires = ["setuptools>=75"]
build-backend = "setuptools.build_meta"

[project]
name = "repository-audit-mcp"
version = "0.1.0"
description = "Read-only bounded repository audit MCP server"
requires-python = ">=3.12,<3.13"
dependencies = []

[project.scripts]
repository-audit-mcp = "repository_audit_mcp.server:main"

[tool.setuptools.packages.find]
where = ["src"]
```

起動は bundled Python 3.12.14 に `PYTHONPATH=src` を与え `python -m repository_audit_mcp.server`。初期検証で packaging install は不要。Git は既存実行ファイルを PATH から発見、なければ E_GIT_UNAVAILABLE。stdout は UTF-8 newline JSON-RPC のみ、stderr は scan_id と error code のみ（source/secret/root は出さない）。stdin 1行最大 2 MiB、過大行は接続を閉じ stderr に E_FRAME_LIMIT。1 client・1 process、1 active scan を許す。別プロセスが同じ cache を開く場合は exclusive lock により起動失敗。共有されたマルチユーザーの対象ではない。

cache は server-owned `LOCALAPPDATA/repository-audit-mcp`（未設定なら home/.cache/repository-audit-mcp）。対象 repository 内の cache path は起動拒否。cache に 0700 相当/所有ユーザー ACL を要求し、state.json と report.json/report.md を atomic replace で保存。target に作るファイルはゼロ。scan ID は UUID4、cache からのみ解決するので ID に任意 path を使えない。retention は終端から 7日、最大 100件。起動時、active がないときに古い終端のみ削除。進行中データは保存後に公開する。cache 保存失敗は E_STORAGE、未永続化の成功を返さず新規 scan を停止する。

## 処理と限界

1. `scan_repository` は絶対 root を canonicalize、Git top-level と同一であること、cache と非包含を検査する。Git は `git --no-optional-locks -c core.fsmonitor=false -C ROOT rev-parse --show-toplevel`、`ls-files -z --cached`、`rev-parse HEAD` の固定 argv、shell=false、stdin=null、timeout=3s、制限付き stdout で起動。repository discovery に user指定 gitconfig/hooks や credential を必要としない。環境の `GIT_*` を除去し `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=os.devnull`。HEAD 不在（unborn）では null を記録。ls-files の NUL を厳密 decode できなければ E_INVENTORY。
2. tracked working tree のみ（変更済み内容を含む）。untracked/ignored/history/submodule 内容は未検査と記録。manifest と inventory の hash、HEAD、dirty にかかわらず読んだ byte の SHA256 を保存。Git checkout 自体は止めないので snapshot consistency は `best_effort`。ファイルの open 前後 stat 不一致は FILE_CHANGED として部分扱い、再試行しない。
3. path は相対 POSIX 表現、`..`/absolute/NUL を拒否、親 components と leaf の symlink/reparse を拒否。canonical containment を open 直前にも確認。POSIX は O_NOFOLLOW、Windows は reparse属性を確認し file identity を open 前後比較。race-free 保証はないので攻撃者が同時変更する対象は非対応。変化検出時即当該fileを閉じ coverage partial。submodule は未検査。対象の書込み権限を必要としない。
4. inventory を相対 path の byte 順に処理。最大 files=5000、file bytes=1 MiB、累計読み込み=50 MiB、wall time=60s（monotonic、root検証を含む）。大きい file は skip、file/total/time 上限は残りを未検査として終端 partial。inventory stdout 2 MiB上限に達したときは不完全一覧を成功とせず E_INVENTORY。byte/file/time の残量を read chunk と各解析／network hop の前に検査。Python AST は 256 KiB 以下、AST 最大 depth=100、node=50000、file解析2s の別 worker processで実施。超過/worker crashは AST_LIMIT。stdlib-only process を kill して回収するので巨大式で server が固まらない。
5. AST rules: PY001 `eval/exec`、PY002 `subprocess` 系の literal `shell=True`、PY003 `pickle.load/loads`、PY004 `yaml.load` の SafeLoader 不在を候補にする。import alias と module-qualified 名を file内で追跡し、名前再代入なら解決不能として check partial。AST位置に証拠を紐づけ、user input到達の証明とは扱わない。PY001/PY003 high、PY002 high、PY004 medium。literal安全性の推論で findings を消さない。syntax/encoding error は AST check partial。
6. SEC001 PEM private-key header と footer の同一file存在=critical、SEC002 JSON/YAML/env のキー `debug` の literal true=medium、SEC003キー `password|api_key|secret|token` の literal非空 value（placeholder `<...>`/`${...}` を除く）=high。対象拡張子は `.py,.pem,.key,.json,.yaml,.yml,.env` と basename `.env`、UTF-8厳密、NUL含む内容は binary として未検査。YAML は依存なしの単行設定ルール、完全 YAML parser と言わない。private-key/key-value 全 value、PEM body、URL credentials を証拠保存前に置換。証拠は最大160文字、SEC001 は `[PRIVATE KEY REDACTED]` のみ。path自体に秘密がある場合まで秘匿保証はしない。
7. npm は package-lock v2/v3 `packages` の name/version/integrity、PyPI は requirements.txt の `name==X`（PEP508 marker/range/editable/hashのみ指定を除外）を扱う。lock v1、workspace/local/VCS、markers、範囲は未検査。resolver実行なし。exact-pin は OSV off の場合も一覧化するが vulnerable/unaffected 判定をしない。結果一覧は1000 distinct pinsまで、残りは未検査。OSV on だけ HTTPS `https://api.osv.dev/v1/query` に package ecosystem/name/version を POST。env proxyを使わず、redirect拒否、TLS標準検証。返却の `next_page_token` を次の request `page_token` に渡す。pinあたり pages=5、総 requests=100、response bytes=1 MiB、hop timeout=min(5s,scan残時間)、retry=0。pagination未完了、network/schema error、quota到達は check partial／未検査、空vulnsによる passed にしない。外部送信は exact package name/versionのみ、root/source/secret は送らない。severity はOSV既知ラベルとCVSS score範囲で正規化、未知はunknown。fixed-versionがあれば remediationに引用、なければ advisory確認を勧める。

既定値の理由: OSV=false は秘密保持とオフライン再現性。5000/1MiB/50MiB は日常 repo の有界負荷、60s は対話型 deadline、AST256KiB/2s は hostile parser対策、1 active は競合とVRAM不要の単純性。100 requests/5pages は外部負荷上限、retry=0 は deadline予測可能性。上限変更は v1 の公開引数にしない。設定の不一致を避け、将来 version変更で明示する。

## MCP と公開 schema

MCP protocolVersion=`2025-11-25`。initialize は clientInfo/protocolVersion/capabilities を検証し serverInfo={name:repository-audit-mcp,version:0.1.0}, capabilities={tools:{listChanged:false}} を返す。別versionは2025-11-25を提示しclientが不一致なら終了。`notifications/initialized` 前の tools call は -32000。tools/list と tools/call、ping を扱う。その他methodは-32601、parse=-32700、invalidrequest=-32600、invalidparams=-32602。notifications は responseなし、未知notificationは無視。MCP request cancellation は応答待ちのrequestを止めるが永続 scan cancel は `cancel_scan` の明示だけ。tools は annotations={readOnlyHint:true,destructiveHint:false,idempotentHint:false,openWorldHint:true}（get_scan は idempotentHint:true/openWorldHint:false、cancel_scan は idempotentHint:true/openWorldHint:false）。OSVは副作用欄で外部送信を明示。

以下は Draft2020-12 の実物 schema bundle。各 tools/list の inputSchema/outputSchema は対象 `$defs` を参照先ごと展開し、外部 `$ref` を残さない。outputSchema は structuredContent の形であり text content には JSON string を併記する。tool失敗は `isError:true` と ErrorOutput structuredContent を返す（protocol errorはJSON-RPC error）。`get_scan` は初期から部分 reportを返す。

```json
{
 "$schema":"https://json-schema.org/draft/2020-12/schema",
 "$defs":{
  "Id":{"type":"string","format":"uuid"},
  "State":{"enum":["queued","running","completed","partial","cancelled","interrupted","failed"]},
  "Coverage":{"enum":["passed","partial","unscanned"]},
  "ScanInput":{"type":"object","additionalProperties":false,"required":["root"],"properties":{"root":{"type":"string","minLength":1,"maxLength":32767},"osv":{"type":"boolean","default":false}}},
  "IdInput":{"type":"object","additionalProperties":false,"required":["scan_id"],"properties":{"scan_id":{"$ref":"#/$defs/Id"}}},
  "Finding":{"type":"object","additionalProperties":false,"required":["id","rule","path","line","evidence","severity","remediation","advisory"],"properties":{"id":{"type":"string","pattern":"^F[0-9]{6}$"},"rule":{"type":"string","maxLength":64},"path":{"type":"string","maxLength":32767},"line":{"type":["integer","null"],"minimum":1},"evidence":{"type":"string","maxLength":160},"severity":{"enum":["critical","high","medium","low","unknown"]},"remediation":{"type":"string","maxLength":1024},"advisory":{"type":["string","null"],"maxLength":256}}},
  "Check":{"type":"object","additionalProperties":false,"required":["check","path","coverage","reason"],"properties":{"check":{"enum":["inventory","python_ast","secret_config","dependencies","osv"]},"path":{"type":["string","null"],"maxLength":32767},"coverage":{"$ref":"#/$defs/Coverage"},"reason":{"type":"string","maxLength":256}}},
  "Report":{"type":"object","additionalProperties":false,"required":["schema_version","root","head","consistency","coverage","limits","progress","checks","findings","notice"],"properties":{"schema_version":{"const":"1"},"root":{"type":"string","maxLength":32767},"head":{"type":["string","null"],"maxLength":64},"consistency":{"const":"best_effort"},"coverage":{"$ref":"#/$defs/Coverage"},"limits":{"type":"object","additionalProperties":false,"required":["files","file_bytes","total_bytes","seconds"],"properties":{"files":{"const":5000},"file_bytes":{"const":1048576},"total_bytes":{"const":52428800},"seconds":{"const":60}}},"progress":{"type":"object","additionalProperties":false,"required":["seen","read","bytes","skipped"],"properties":{"seen":{"type":"integer","minimum":0},"read":{"type":"integer","minimum":0,"maximum":5000},"bytes":{"type":"integer","minimum":0,"maximum":52428800},"skipped":{"type":"integer","minimum":0}}},"checks":{"type":"array","maxItems":16000,"items":{"$ref":"#/$defs/Check"}},"findings":{"type":"array","maxItems":1000,"items":{"$ref":"#/$defs/Finding"}},"notice":{"const":"静的調査の限定的観測です。安全性を保証しません。"}}},
  "SuccessOutput":{"type":"object","additionalProperties":false,"required":["ok","scan_id","state","revision","report","markdown"],"properties":{"ok":{"const":true},"scan_id":{"$ref":"#/$defs/Id"},"state":{"$ref":"#/$defs/State"},"revision":{"type":"integer","minimum":1},"report":{"$ref":"#/$defs/Report"},"markdown":{"type":"string","maxLength":1572864}}},
  "ErrorOutput":{"type":"object","additionalProperties":false,"required":["ok","error"],"properties":{"ok":{"const":false},"error":{"type":"object","additionalProperties":false,"required":["code","message","retryable","scan_id"],"properties":{"code":{"enum":["E_NOT_GIT","E_GIT_UNAVAILABLE","E_ROOT","E_BUSY","E_NOT_FOUND","E_STORAGE","E_INVENTORY","E_INTERNAL"]},"message":{"type":"string","maxLength":256},"retryable":{"type":"boolean"},"scan_id":{"oneOf":[{"$ref":"#/$defs/Id"},{"type":"null"}]}}}}},
  "ToolOutput":{"oneOf":[{"$ref":"#/$defs/SuccessOutput"},{"$ref":"#/$defs/ErrorOutput"}]},
  "RpcError":{"type":"object","additionalProperties":false,"required":["jsonrpc","id","error"],"properties":{"jsonrpc":{"const":"2.0"},"id":{"type":["string","integer","null"]},"error":{"type":"object","additionalProperties":false,"required":["code","message"],"properties":{"code":{"enum":[-32700,-32600,-32601,-32602,-32000]},"message":{"type":"string","maxLength":256}}}}}
 }
}
```

tools/list は `scan_repository: ScanInput -> ToolOutput`, `get_scan: IdInput -> ToolOutput`, `cancel_scan: IdInput -> ToolOutput`。invalid inputは-32602で scanを作らない。root絶対性は semantic validation E_ROOT。schema format uuidも runtimeで検証。markdown は title/scan/state/limits/coverage/check reasons/findings/remediation/notice の順。HTML escape・code fence escapeを施し source をリンクURLとして扱わない。findings1000超過は残りcountと FINDING_LIMIT をcheck reasonへ、coverage partial。checks16000/markdown1.5MiB/report2MiB超過は要約checkに集約し partial、黙って落とさない。最大line長やroot長を含めserializationサイズを保存前に検査する。

## 状態・取消・再起動

state.json の durable record は scan_id/root/osv/state/revision/created_at/updated_at/deadline/result_hash/report参照/各読込hash/取消flag を持つ。進捗は file単位commit。stateとreportの世代を同じrevision directoryに保存、最後にcurrent pointerをatomic replace。破損世代は起動時隔離し E_STORAGEを返す。部分結果は commit済みだけ返す。

| server-owned state | scan_repository | get_scan | cancel_scan |
|---|---|---|---|
| no scan | queuedを保存し返す | E_NOT_FOUND | E_NOT_FOUND |
| queued/running | E_BUSY | 最新commit部分結果 | cancel flag保存、cancelled部分結果へ |
| completed/partial | 新ID queued | 保存済み結果 | 同じ終端結果（冪等） |
| cancelled/interrupted/failed | 新ID queued | 保存済み結果 | 同じ終端結果（冪等） |

queued→running→completed/partial、queued/running→cancelled/interrupted/failed のみ。completed は全要求checkがpassedの場合だけ、OSV off/非対応fileありはpartial。passed は「該当checkの対象処理完了」、findingゼロや安全を意味しない。unscanned は対象checkを一度も完了していない、partial は一部完了。workerは cancel/deadlineをchunk、AST終了、OSV hop前後で確認する。cancel応答まで最大hop5s+commit1s、cancelledを保存するまで成功応答しない。終了競合はstore lock下で先に保存した終端が勝つ。restartはqueued/runningをinterruptedに変更し保存、既存結果を保持し自動再開なし。接続切断は scanを継続、process停止は次起動でinterrupted。worker crashはfailed、正常に検査できた部分があればreport保持。内部例外のmessageは固定code説明でpath/source/stackを含めない。

## 失敗・機構・副作用

| 状況 | 結果・機構 | 副作用／保持 |
|---|---|---|
| 非Git/不存在/不適合root | E_NOT_GIT/E_ROOT、scan作成前拒否 | target変更なし、rootをログしない |
| Git無し／inventory timeout | E_GIT_UNAVAILABLE/E_INVENTORY | subprocessをkill、cacheに失敗recordのみ |
| unreadable/binary/symlink/変化 | check未検査またはpartial、継続 | target変更なし、既読hash保持 |
| AST parse/limit/crash | check partial、継続 | AST child kill、redacted証拠のみ |
| secret検出 | finding、severityはルール定数 | 生secretは永続化もログもしない |
| OSV off/range/上限/timeout/bad response | check unscanned/partial | on時のみpackage情報送信、無retry |
| deadline/cancel/restart | partial/cancelled/interrupted | commit済み部分reportを保存 |
| quota/output limit | partial、理由と省略数 | memory/output上限を維持 |
| storage full/lock/permission | E_STORAGE、受付停止 | 未commit結果を成功扱いしない |
| unknown ID/malformed input | E_NOT_FOUND/-32602 | scan作成なし |

## 受入・根拠

独立 verifier は temporary Git repo に safe.py、各PY rule、private-key dummy、debug.env、exact requirements/package-lock、range、binary、symlink、unreadable、巨大file、parse-error を配置し `git add`。Git/fixtures の作成は検証用環境だけ、serverは対象作成しない。真 stdio client が initialize→initialized→tools/list→scan_repository→get_scan polling→cancel_scan を呼び、JSON schema検証とMarkdown同値性を検査する。schema検証には verifier環境の既存validatorを使うか独立fixture assertion、server runtime依存には追加しない。

正常fixtureではPY/SEC位置・severity・remediation一致、private-key body/secret値が全cache/stdout/stderr/Markdownに存在しないこと、file treeと全tracked bytes/modeがscan前後一致することを確認。safe-onlyでもnoticeがあり保証表現なし。OSVはstdlib fake HTTPS endpointを依存境界で差し替え、2page/next_page_token、100req、badJSON、timeout、redirectを検証し production originは固定。外部liveOSVはoptional小数pin smokeのみ、offline受入と混同しない。cancelはqueued/running両方、cancel/complete競合、process kill→restart interrupted、E_BUSY、未知ID、cache故障、frame過大、protocol順序も真MCPで確認。時間/size限界は下限注入したfixtureと既定値の境界case両方を使う。証拠はMCP transcript/redacted report/schema結果/target hash比較/終了stateを保存する。合否は独立verifier、未実装状態で試験済みとは言わない。

全18 `design.harness` 基準は session `rl_01M4B5757XDB38G9X8PEGFFACN` の frozen rubric snapshot（canonical参照 `.strict-goal/design-state.json`）を正本とする。検証はその18件すべての criterion ID に本書の該当節と受入証拠を対応付け、未検証を明示する。本書に別rubricや自己採点を作らない。
