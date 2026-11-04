# Records docs/demo.gif for the README. Re-record after a release: vhs docs/demo.tape
# Uses the local bundle (pnpm --filter scrappy-redact bundle) so the demo matches the code.
Output docs/demo.gif

Set Shell "bash"
Set FontSize 17
Set Width 1180
Set Height 440
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms
Set WindowBar Colorful

Hide
Type "export PS1='$ ' SCRAPPY_NO_UPDATE_CHECK=1 XDG_CONFIG_HOME=$(mktemp -d) REPO=$PWD && alias scrappy='node $REPO/apps/cli/dist/scrappy.js' && cd $(mktemp -d)" Enter
Type `printf '%s\n' 'ERROR payment declined user=maria@shopfast.io card=4111 1111 1111 1111' 'WARN  db retry DATABASE_URL=postgres://app:Tr0ub4dor-3@db.internal:5432/shop' 'DEBUG auth Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9.c2lnbmF0dXJlLW5vdC1yZWFs' 'INFO  sms sent to +251 911 234 567, webhook sig=Zt7Kp2Qw9Xr4Lm8Vn3Bc6Hy1Jd5Fg0Sa' 'INFO  deploy commit=9f86d081884c req=3f6c2a9e-8b1d-4c7a-9e2f-1a2b3c4d5e6f ok' > app.log` Enter
Type "clear" Enter
Show

Type "cat app.log" Sleep 400ms Enter
Sleep 2.5s
Type "scrappy sanitize -i app.log" Sleep 400ms Enter
Sleep 5s
