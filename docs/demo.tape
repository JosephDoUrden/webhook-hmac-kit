# Renders docs/demo.gif. Run from the repo root: vhs docs/demo.tape
#
# The hidden preamble installs 1.0.0 and 2.0.0 side by side in a temp dir and copies the
# two scripts from docs/demo/ next to them. Needs network for the two npm installs.

Output docs/demo.gif

Require node
Require npm

Set Shell bash
Set FontSize 20
Set Width 1280
Set Height 720
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Framerate 20
Set WaitTimeout 120s

Hide
Type "repo=$PWD" Enter
Type "cd $(mktemp -d)" Enter
Type "cp -r $repo/docs/demo/old $repo/docs/demo/new ." Enter
Type "npm i --prefix old webhook-hmac-kit@1.0.0 --silent --no-audit --no-fund" Enter
Wait
Type "npm i --prefix new webhook-hmac-kit@2.0.0 --silent --no-audit --no-fund" Enter
Wait
Type "clear" Enter
Show

Type "cat old/resplit.mjs" Sleep 300ms Enter
Sleep 3500ms
Type "node old/resplit.mjs" Sleep 300ms Enter
Sleep 4500ms

Type "clear" Enter
Type "cat new/resplit.mjs" Sleep 300ms Enter
Sleep 4s
Type "node new/resplit.mjs" Sleep 300ms Enter
Sleep 6s
