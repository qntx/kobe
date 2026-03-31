Output demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 600

Hide
Type "clear"
Enter
Show

# 1. Generate Bitcoin wallet
Type "kobe btc new"
Sleep 500ms
Enter
Sleep 3s

Ctrl+L

# 2. Generate Ethereum wallet
Type "kobe evm new"
Sleep 500ms
Enter
Sleep 3s

Ctrl+L

# 3. Generate Solana wallet
Type "kobe svm new"
Sleep 500ms
Enter
Sleep 3s

Ctrl+L

# 4. Generate Ethereum wallet with 3 addresses
Type 'kobe evm new -c 3'
Sleep 500ms
Enter
Sleep 3s

Ctrl+L

# 5. Advanced: Taproot + 24 words + 2 addresses
Type "kobe btc new -a taproot -w 24 -c 2"
Sleep 500ms
Enter
Sleep 4s

Ctrl+L

# 6. JSON output for scripts & agents
Type "kobe evm new --json"
Sleep 500ms
Enter
Sleep 3s

Ctrl+L

# 7. Import from existing mnemonic
Type 'kobe evm import -m "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"'
Sleep 500ms
Enter
Sleep 3s

Ctrl+L

# 8. Mnemonic camouflage
Type 'kobe mnemonic encrypt -m "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" -p "secret"'
Sleep 500ms
Enter
Sleep 5s
