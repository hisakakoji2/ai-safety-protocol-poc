# AI Safety Protocol: Proof of Concept

[日本語は下にあります](#日本語)

A working proof of concept of an AI safety protocol in which **cheating never pays**. It is built from three parts, each modelled on a mechanism that already runs at scale. No blockchain and no token are used.

| Part | What it does | Modelled on |
| --- | --- | --- |
| Record | Each AI action's fingerprint (a salted hash) is appended to a tamper-evident log. The company keeps the content. Independent witnesses cosign the log's tree heads. | Certificate Transparency ([RFC 9162](https://www.rfc-editor.org/rfc/rfc9162)) |
| Lottery audit | Public randomness picks actions for deep audit, with probability proportional to their declared impact. | Tax audits, acceptance sampling |
| Fine formula | fine = damage / (audit probability × detection rate). The expected fine equals the damage. | Becker (1968) |

The same weights give an unbiased estimate of total damage from the audited sample alone (Horvitz–Thompson), which is the basis for an insurance premium.

## Run it

Requires Python 3.10+.

```bash
pip install -r requirements.txt
python -m ai_safety_poc.demo        # about 20 seconds
python -m unittest discover -s tests
```

`python -m ai_safety_poc.demo --help` lists options (periods, actions, violation rate, auditor detection rate, seed).

## What the demo shows

Default run: 40 audit periods, 1,000 actions per company per period, the cheater violates 5% of the time, and auditors catch 70% of the violations they examine.

| Result | Fines corrected with canaries | Fines not corrected |
| --- | --- | --- |
| Honest company's fines | 0 yen | 0 yen |
| Cheater's gain from violations | 316,866,411 yen | 317,529,936 yen |
| Cheater's fines | 327,980,364 yen | 220,510,913 yen |
| **Cheater's net gain** | **−4% of gain** | **+31% of gain** |
| Damage estimated from audits vs truth | +3.5% | −30.6% |

Measuring the auditors' miss rate with planted test violations ("canaries") is what makes cheating unprofitable. The demo also shows a witness catching a log operator who **rewrites history**, and a **split view** (different histories shown to different witnesses) being caught when cosignatures are compared.

## Code map

| File | Contents |
| --- | --- |
| `ai_safety_poc/merkle.py` | Merkle tree, inclusion and consistency proofs (RFC 9162) |
| `ai_safety_poc/ledger.py` | Action commitments, signed receipts and signed tree heads |
| `ai_safety_poc/witness.py` | Witness cosigning, rewrite and rollback detection, split-view detection, quorum check |
| `ai_safety_poc/audit.py` | Audit probability, public-randomness lottery, auditor model, canary estimate |
| `ai_safety_poc/fines.py` | Fine formula, Horvitz–Thompson estimate, premium |
| `ai_safety_poc/protocol.py` | One audit period end to end |
| `ai_safety_poc/demo.py` | The four-part demonstration |

## Design notes

- **The lottery cannot be gamed.** The audit probability depends only on the declared impact already fixed in the log, and the random draw uses a beacon published after the period's tree head is cosigned. Under-declaring impact, or failing to open a selected commitment, is itself a violation and draws the maximum fine.
- **Bounded fines.** With honest declarations, actions below the cap (1,000,000 yen by default) are fined at most the cap. Actions at or above the cap are always audited and fined exactly their damage, with no multiplier; that part is ordinary liability that insurance can cover.
- **One honest witness is enough** to detect a rewritten history, and comparing cosigned tree heads across witnesses detects a split view.

## Limitations

This is a proof of concept, not production software.

- Everything runs in one process and in memory. A real deployment needs a networked log service, a witness network and persistent storage.
- The public beacon is a stand-in. A real deployment would use an external beacon such as drand or the NIST Randomness Beacon.
- Auditors are modelled as a detection probability. How well real experts and AI catch violations must be measured.
- The cryptography uses standard primitives (SHA-256, Ed25519) but the code has not been security-audited.

---

## 日本語

**違反しても得をしない**AI安全プロトコルの、動作するPoC(概念実証)です。3つの部品でできており、どれもすでに大規模に動いている仕組みを手本にしています。ブロックチェーンや独自通貨は使いません。

| 部品 | 内容 | 手本 |
| --- | --- | --- |
| 記録 | AIの行動ごとに、その指紋(ソルト付きハッシュ)を改ざんが分かる台帳に追記する。中身は企業が手元に保管する。独立した立会人が台帳の状態に連名で署名する | 証明書透明性([RFC 9162](https://www.rfc-editor.org/rfc/rfc9162)) |
| くじ監査 | 公開の乱数で、申告された影響額に比例した確率で行動を選び、専門家が深く監査する | 税務調査、抜き取り検査 |
| 罰金の式 | 罰金 = 損害 ÷(監査確率 × 発見率)。罰金の期待値は損害額と等しくなる | Becker(1968) |

同じ重みを使うと、監査したサンプルだけから事故の総額を偏りなく推定でき(Horvitz–Thompson推定)、保険料の根拠になります。

### 動かし方

Python 3.10以上が必要です。

```bash
pip install -r requirements.txt
python -m ai_safety_poc.demo        # 約20秒
python -m unittest discover -s tests
```

### デモで分かること

標準設定:40期間、各社が1期間に1,000件の行動、違反する企業は5%の確率で違反、監査人は調べた違反の70%を見つける。

| 結果 | 見落とし率で補正した罰金 | 補正しない罰金 |
| --- | --- | --- |
| 正直な企業の罰金 | 0円 | 0円 |
| 違反企業が違反で得た利益 | 316,866,411円 | 317,529,936円 |
| 違反企業の罰金 | 327,980,364円 | 220,510,913円 |
| **違反企業の差し引き** | **利益の−4%** | **利益の+31%** |
| 監査から推定した損害額と実際の差 | +3.5% | −30.6% |

試験用の偽の違反で監査人の見落とし率を測り、罰金を補正することで、違反が割に合わなくなります。補正しないと、違反企業は利益の約3割を手にします。デモでは他に、**過去を書き換えた**台帳の運営者を立会人が見抜く様子と、立会人ごとに**違う記録を見せる二枚舌**が署名の照合で見つかる様子も示します。

### 設計上のポイント

- **くじはごまかせない**:監査確率は台帳に記録済みの申告影響額だけで決まり、乱数はその期間の記録が署名された後に公開されます。影響額の過少申告や、選ばれた行動の中身を開示しないことは、それ自体が違反として最大の罰金になります。
- **罰金には上限がある**:正直に申告していれば、影響額が上限(標準100万円)未満の行動の罰金は最大100万円です。上限以上の行動は必ず監査され、罰金は損害額そのもの(割り増しなし)です。この部分は通常の賠償責任で、保険で備えられます。
- **正直な立会人が1人いれば**、過去の書き換えは見つかります。立会人の署名を照合すれば、二枚舌も見つかります。

### 制約

これはPoCであり、本番用のソフトウェアではありません。

- すべて1つのプロセスのメモリ上で動きます。実運用には、ネットワーク上の台帳サービス、立会人のネットワーク、永続的な保存が必要です。
- 公開乱数は仮のものです。実運用ではdrandやNISTの乱数ビーコンなど外部のものを使います。
- 監査人は「発見率」という確率でモデル化しています。実際の専門家やAIの発見率は測定が必要です。
- 暗号には標準的な方式(SHA-256、Ed25519)を使っていますが、セキュリティ監査は受けていません。
