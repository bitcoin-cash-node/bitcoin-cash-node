# chaintxdata

Generate `ChainTxData` C++ code snippets from live node RPC data using `getchaintxstats`.

## Features

- Query block hash and transaction stats via `getchaintxstats`
- Compute `tx_rate` from the delta of `txcount` divided by the delta of block timestamps
- Selectable output templates (mainnet verbose, testnet compact)
- RPC authentication from `bitcoin.conf`

## Files

| File | Description |
|------|-------------|
| `make_chaintxdata.py` | Main script to query RPC and generate ChainTxData |
| `chaintxdata.cpp.tmpl` | Default mainnet output template (verbose format) |
| `chaintxdata-testnet.cpp.tmpl` | Testnet output template (compact format) |

### Examples

**Mainnet:**
```bash
python make_chaintxdata.py \
    --address 127.0.0.1:8332 \
    --config /mnt/bitcoin/bchn/mainnet/bitcoin.conf \
    --block 960730 --last-block 930654
```

**Testnet:**
```bash
python make_chaintxdata.py \
    --address 127.0.0.1:18332 \
    --config /mnt/bitcoin/bchn/testnet/bitcoin.conf \
    --template chaintxdata-testnet.cpp.tmpl \
    --block 1720199 --last-block 1689425
```

**Testnet4:**
```bash
python make_chaintxdata.py \
    --address 127.0.0.1:28332 \
    --config /mnt/bitcoin/bchn/testnet4/bitcoin.conf \
    --template chaintxdata-testnet.cpp.tmpl \
    --block 315656 --last-block 278588
```

**Chipnet:**
```bash
python make_chaintxdata.py \
    --address 127.0.0.1:48332 \
    --config /mnt/bitcoin/bchn/chipnet/bitcoin.conf \
    --template chaintxdata-testnet.cpp.tmpl \
    --block 315659 --last-block 285268
```
