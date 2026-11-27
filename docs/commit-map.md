# Commit map (history rewrite)

The repository history was rewritten before publication. The rewrite edited
commit messages, removed a local notes file from every commit, and removed
editor-specific lines from `.gitignore`. Source code, tests, attack payloads,
the dataset and the results files are unchanged, and every commit keeps its
original author, committer and dates.

Results files in `eval/results/` (and the hashes quoted in the README) record
the **original** hashes in the left column. Use this table to find the commit
that holds the same code today.

Two original commits changed only the removed notes file, so they no longer
exist on their own. They map to the commit with the same code (marked *).

| Original commit | Current commit |
|---|---|
| `ac077ad2ad2a1ac02a5e27b622d662d72342e9ff` | `cd31a7ecffbaa023ff9848c7b42be7b4eef24118` |
| `4f2c60f00fc3e816d0f9ae8bcacb7d5b79f61e64` | `989c0fe384c8347d67491df5b35b19fca0cce353` |
| `c9cbb37e93a8878fa876edec8071f5032388dc28` | `2efadca8eccce4cd1a2de38e02a1ec45788cc76e` |
| `040055a4c41193ec540481ef9f8ed7a15f665daa` | `422d2e48b7adc34bcc7afd694cb1c5afa7f3225f` |
| `03f0a8bc3c85dda5046c36d80d08865bd3d17e1c` | `613bd40548c3f68c69582ceabaed67274d74c59c` |
| `cb4b130a1f480fccc4b8d9e51ab6cb3035b0efd0` | `defd7f00dbd4394f12d33f48295b7817f89587f0` |
| `5713d7c9c453a5e427cbc69b64ff14a259244e00` | `c1bb29f12860b223c7336f56e4cb2e94c3bddd7e` |
| `28eb4e3bbbc6cb3a8c08da39840caed06b4360a3` | `c1bb29f12860b223c7336f56e4cb2e94c3bddd7e` * |
| `2e16e4f17db71485c76485ffec2caa112f03c715` | `6c8687fdb865e4e10fb8044b0c1e88fec447cf04` |
| `294667f0b33c71579b71c2d6a5fde98500b076f7` | `0d78f920a9b88e2db1c9f50d4afad96a87fcab37` |
| `40b2b74a2d8714a1842dfc4bbedcc10719c9dc3d` | `48b4f3535ee3853d839637adf825cea13feaeee7` |
| `d459c614be6d7e0dd869cc06b0edc7d36048e7d2` | `48b4f3535ee3853d839637adf825cea13feaeee7` * |
| `a1e02c9507d2950242cff77a01a25500982ffb84` | `346e95c5f40c9224f7e845c2bbc1236487d3bc11` |
| `b70e16cc06060e58daba42b065adb8102385a1f4` | `fdfb84520e1e5b52009a29e8a173b2b5304718ea` |
