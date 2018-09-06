# privacy-exposer

privacy-exposerはTor/I2Pを別のSOCKSプロクシへ、それ以外は踏み台としてのみ振る舞う単純なSOCKSプロクシです。

## 動作要件

* C99
* `vsyslog()`が公開されること。NetBSDでは`CFLAGS`に`-D_NETBSD_SOURCE`の追加が必要。

## 使い方

環境変数`BIND_ADDR`, `BIND_PORT`, `UPSTREAM_ADDR`, `UPSTREAM_PORT`を設定した上で以下を実行します。

```
privacy-exposer [-p pidfile]
```

## ライセンス

MITライセンス
