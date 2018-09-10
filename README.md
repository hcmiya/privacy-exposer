# privacy-exposer

privacy-exposerはTor/I2Pを別のSOCKSプロクシへ、それ以外は踏み台としてのみ振る舞う単純なSOCKSプロクシです。

## コンパイル・動作要件

* C99
* POSIX.1-2008
* `vsyslog()`が公開されること。NetBSDでは`CFLAGS`に`-D_NETBSD_SOURCE`の追加が必要。

## 使い方

次のコマンドでSOCKS5サーバーが起動します。`bind-addr`、`bind-port`が省略されたときの初期値はそれぞれ`localhost`、`9000`です。

```
privacy-exposer [-p pidfile] [-l loglevel] [-r rule-config] [bind-addr bind-port]
```

`-r`で、宛先に応じたプロクシ接続のルールが書かれたファイルを指定します。書式は以下のサンプルを見て雰囲気を感じ取ってください。

```
; comment
; このルールは上から順番に検査されます
host .onion    socks5 localhost   9050 ; 宛先ホスト末尾が.onionの場合はlocalhost:9050へsocks5で接続
host .i2p#80   socks5 192.168.3.1 4447 ; 宛先ホスト末尾が.i2p且つポートが80の場合は192.168.3.1へsocks5で接続
host localhost deny                    ; 宛先ホストがlocalhostに一致するときは接続を拒否
host #80,443                           ; 宛先が任意のホストでポートが80または443のときはサーバーから直接接続
host #         deny                    ; 任意の宛先、任意のポートのときは接続を拒否
```

`-p`を指定すると`pidfile`にPIDを書き込んだ上でデーモン化します。

## ライセンス

MITライセンス
