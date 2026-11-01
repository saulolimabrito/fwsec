# Contributing to fwsec

Contributions are accepted through pull requests. Do not push directly to `main`.

## Required workflow

1. Create a branch from `main`.
2. Make a small, self-contained change.
3. Run the applicable validation commands.
4. Update the documentation whenever public behavior changes.
5. Open a pull request describing the change, motivation, impact, and tests.
6. Merge the pull request after review.

`CODEOWNERS` assigns every file to `@saulolimabrito`, the project maintainer.

## Minimum validation

```bash
python3 -m compileall -q src
bash -n install.sh
```

When available, also run:

```bash
ruff check src
mypy src
```

## Security

Do not include credentials, tokens, internal IP addresses, customer data, or production configuration. Report vulnerabilities privately by following [SECURITY.md](SECURITY.md); do not open a public issue.

## License

By contributing, you agree that your contribution is licensed under the project's [GNU General Public License version 2 only](LICENSE), SPDX identifier `GPL-2.0-only`.
