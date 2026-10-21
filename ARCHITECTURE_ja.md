# アーキテクチャ:関係者・流れ・つながり

[English](ARCHITECTURE.md)

このPoCに登場する関係者と、1回の監査期間の流れ、不正の見抜き方、コードとの対応を図で示す。

## 1. 関係者とつながり

AI企業は行動の指紋を記録台帳に残し、中身は手元に保管する。立会人が台帳を見張り、くじで選ばれた行動だけを監査人が調べる。監査結果は罰金と保険料の両方に使われる。

```mermaid
flowchart TB
    subgraph USE["AIを使う側"]
        direction LR
        C["AI企業<br/>AIエージェントを運用<br/>行動の中身を手元に保管"]
        T["取引相手・利用者<br/>受領証と連名署名を確認"]
    end

    subgraph RECORD["記録を守る側"]
        direction LR
        L["記録台帳<br/>指紋を追記・受領証を発行<br/>ledger.py / merkle.py"]
        W["立会人<br/>大学・損保・他社 など<br/>witness.py"]
    end

    subgraph CHECK["監査と補償"]
        direction LR
        B["公開乱数ビーコン<br/>drand・NIST など<br/>PoCでは代用"]
        AU["監査人<br/>専門家とAI<br/>audit.py"]
        I["保険会社<br/>保険料を算出<br/>fines.py"]
    end

    C -- "① 行動の指紋と申告影響額" --> L
    L -- "② 署名つき受領証" --> C
    C -- "③ AIの操作 + 受領証" --> T
    L -- "④ ツリーヘッド + 一貫性証明" --> W
    W -- "⑤ 連名署名" --> T
    B -- "⑥ 乱数(連名署名の後)" --> AU
    AU -- "⑦ 選ばれた行動の中身を要求<br/>⑧ 違反なら罰金" --> C
    AU -- "⑨ 監査結果" --> I
```

## 2. 1回の監査期間の流れ

`protocol.py` の `Protocol.submit` と `Protocol.close_period` が、この流れを1期間分実行する。

```mermaid
sequenceDiagram
    autonumber
    participant C as AI企業
    participant L as 記録台帳
    participant W as 立会人
    actor T as 取引相手
    participant B as 公開乱数
    participant AU as 監査人
    participant I as 保険会社

    C->>L: 行動の指紋(ソルト付きハッシュ)と申告影響額を追記
    L-->>C: 署名つき受領証
    C->>T: AIの操作と受領証
    Note over T: 受領証のない操作は受け付けない
    Note over L,W: 期間の終わり
    L->>W: 署名つきツリーヘッドと一貫性証明
    Note over W: 前回から「追記しただけ」かを検証<br/>書き換えがあれば警報
    W-->>T: 連名署名
    Note over T: 定足数(PoCでは2者)の連名署名がある記録だけを信用
    B-->>AU: 乱数を公開(連名署名の後なので企業は事前に予測できない)
    Note over AU: くじ:監査確率 = 申告影響額 ÷ 100万円<br/>(下限0.1%、上限100%)
    AU->>C: 選ばれた行動の中身の開示を要求
    C-->>AU: 中身とソルト(指紋と一致するか確認)
    Note over AU: 偽の違反を混ぜて自分たちの発見率を測定
    AU->>C: 違反があれば 罰金 = 損害 ÷(監査確率 × 発見率)
    AU->>I: 監査結果
    Note over I: 監査結果だけから事故の総額を推定<br/>(Horvitz–Thompson推定)し、保険料を算出
```

## 3. 誰の不正を、誰が見抜くか

不正をする可能性があるのは、AI企業と記録台帳の運営者の両方。どちらの不正にも、見抜く仕組みと結果が決まっている。

```mermaid
flowchart LR
    subgraph COMPANY["AI企業の不正"]
        V1["AIが違反する"]
        V2["影響額を少なく申告する<br/>(監査確率を下げるため)"]
        V3["選ばれた行動の中身を開示しない"]
    end

    subgraph LOG["記録台帳の運営者の不正"]
        V4["過去の記録を書き換える"]
        V5["相手によって違う記録を見せる<br/>(二枚舌)"]
    end

    D1["監査人がくじ監査で発見<br/>発見率は偽の違反で補正"]
    D2["立会人が一貫性証明で検出<br/>正直な立会人が1人いれば足りる"]
    D3["立会人どうしの連名署名を照合<br/>同じサイズで根が2つあれば検出"]

    R1["罰金 = 損害 ÷(監査確率 × 発見率)<br/>期待値は損害額と同じ"]
    R2["最大の罰金"]
    R3["警報・その記録は信用されない"]

    V1 --> D1
    V2 --> D1
    V3 --> D1
    D1 -- "AIの違反" --> R1
    D1 -- "申告・開示の違反" --> R2
    V4 --> D2 --> R3
    V5 --> D3 --> R3
```

## 4. コードの構成

矢印は「使う」関係。暗号には SHA-256 と Ed25519 だけを使い、ブロックチェーンや独自通貨は使わない。

```mermaid
flowchart TB
    DEMO["demo.py<br/>4部構成のデモ"]
    PROTO["protocol.py<br/>1期間の実行"]
    LEDGER["ledger.py<br/>行動の指紋・受領証・ツリーヘッド"]
    WIT["witness.py<br/>連名署名・書き換えと二枚舌の検出"]
    AUD["audit.py<br/>監査確率・くじ・監査人・発見率の測定"]
    FINES["fines.py<br/>罰金の式・事故総額の推定・保険料"]
    MERKLE["merkle.py<br/>Merkle木・包含証明・一貫性証明<br/>(RFC 9162)"]
    CRYPTO["crypto.py<br/>Ed25519署名・正規化"]

    DEMO --> PROTO
    PROTO --> FINES
    PROTO --> AUD
    PROTO --> LEDGER
    PROTO --> WIT
    WIT --> LEDGER
    LEDGER --> MERKLE
    LEDGER --> CRYPTO
    WIT --> MERKLE
    WIT --> CRYPTO
    AUD --> LEDGER
```

## PoCと実運用の違い

| 部分 | このPoC | 実運用で必要なもの |
| --- | --- | --- |
| 記録台帳 | 1プロセスのメモリ上 | ネットワーク上のサービスと永続的な保存 |
| 立会人 | 同じプロセス内の3者 | 独立した組織が運営する立会人のネットワーク |
| 公開乱数 | 固定の文字列から作る代用品 | drand や NIST の乱数ビーコン |
| 監査人 | 発見率という確率でモデル化 | 実際の専門家とAI。発見率は実測が必要 |
| 取引相手・保険会社 | 検証関数と推定関数として実装 | 各社のシステムへの組み込み |
