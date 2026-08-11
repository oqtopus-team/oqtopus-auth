<!-- markdownlint-disable MD041 -->
![OQTOPUS logo](./docs/asset/oqtopus-logo.png)

# OQTOPUS Auth

[![CI](https://github.com/oqtopus-team/oqtopus-auth/actions/workflows/ci.yaml/badge.svg)](https://github.com/oqtopus-team/oqtopus-auth/actions/workflows/ci.yaml)
[![codecov](https://codecov.io/gh/oqtopus-team/oqtopus-auth/graph/badge.svg?token=4XTC9HSSFV)](https://codecov.io/gh/oqtopus-team/oqtopus-auth)
[![pypi version](https://img.shields.io/pypi/v/oqtopus-auth.svg)](https://pypi.org/project/oqtopus-auth/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![slack](https://img.shields.io/badge/slack-OQTOPUS-pink.svg?logo=slack&style=plastic)](https://join.slack.com/t/oqtopus/shared_invite/zt-3bpjb7yc3-Vg8IYSMY1m5wV3DR~TMSnw)

## Overview

**OQTOPUS Auth** is a framework-agnostic authentication and authorization
library for the OQTOPUS ecosystem. It ships pluggable authentication
providers (disabled auth, and reverse-proxy-injected JWT headers) plus a
role/permission model, with an optional FastAPI integration.

```shell
pip install oqtopus-auth
# or, with FastAPI middleware and dependencies:
pip install "oqtopus-auth[fastapi]"
```

## Documentation

- [Documentation Home](https://oqtopus-auth.readthedocs.io/)

## Citation

You can use the DOI to cite oqtopus-auth in your research.

[![DOI](https://zenodo.org/badge/1330600402.svg)](https://zenodo.org/badge/latestdoi/1330600402)

Citation information is also available in the [CITATION](https://github.com/oqtopus-team/oqtopus-auth/blob/main/CITATION.cff) file.

## Contact

You can contact us by creating an issue in this repository or by email:

- [oqtopus-team[at]googlegroups.com](mailto:oqtopus-team[at]googlegroups.com)

## License

oqtopus-auth is released under the [Apache License 2.0](LICENSE).
